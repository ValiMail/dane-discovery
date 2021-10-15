"""DANE class definition."""
import binascii
import hashlib
import re
import requests
import urllib
from urllib.parse import urlparse
from urllib.parse import urlunparse

import dns.resolver
import dns.dnssec
from dns.resolver import Resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from forcediphttpsadapter.adapters import ForcedIPHTTPSAdapter

from .exceptions import TLSAError
from .pki import PKI


class DANE:
    """Abstract interactions involved in certificate retrieval."""

    descr = {"certificate_usage":
             {0: "CA Constraint",
              1: "PKIX-EE",
              2: "DANE-TA",
              3: "DANE-EE",
              4: "PKIX-CD"},
             "selector":
             {0: "Full certificate match",
              1: "Public key match"},
             "matching_type":
             {0: "Exact match against certificate association",
              1: "Match the SHA-256 hash of the selected content",
              2: "Match the SHA-512 hash of the selected content"}}

    @classmethod
    def generate_tlsa_record(cls, certificate_usage, selector,
                             matching_type, certificate):
        """Return the bytes for a TLSA record.

        Detailed information on the fields of the TLSA record can be found
        `here <https://https://tools.ietf.org/html/rfc6698/>`_

        Args:
            certificate_usage (int): Certificate usage variable (0-3).
            selector (int): Selector (0|1).
            matching_type (int): Matching type. Only support ``0`` for
                certificate discovery.
            certificate (bytes): Certificate in PEM or DER format.

        Return:
            bytes: TLSA record in bytes.

        Raise:
            TLSAError if unsupported options are used.
        """
        x509_obj = PKI.build_x509_object(certificate)
        cert_bytes = PKI.serialize_cert(x509_obj, "DER")
        if matching_type == 0:
            certificate_association = binascii.hexlify(cert_bytes).decode()
        elif matching_type == 1:
            certificate_association = cls.generate_sha_by_selector(certificate,
                                                                   "sha256",
                                                                   selector)
        elif matching_type == 2:
            certificate_association = cls.generate_sha_by_selector(certificate,
                                                                   "sha512",
                                                                   selector)
        else:
            err_msg = "Invalid matching type {}.".format(matching_type)
            raise TLSAError(err_msg)
        tlsa_rr = "{} {} {} {}".format(certificate_usage, selector,
                                       matching_type,
                                       certificate_association)
        return tlsa_rr

    @classmethod
    def generate_sha_by_selector(cls, certificate, sha, selector):
        """Return the SHA value appropriate for the selector.

        Args:
            certificate (bytes): Certificate in PEM or DER format.
            sha (str): Valid values: ``sha256``, ``sha512``.
            selector (int): Valid values: ``0``, ``1``. If ``0``, we
                generate a SHA for the entire certificate. If ``1``, we
                generate a SHA only on the public key in the certificate.

        Return:
            bytes: Base64 representation of SHA.
        """
        valid_selectors = [0, 1]
        valid_hashing_algos = {"sha256": hashlib.sha256,
                               "sha512": hashlib.sha512}
        x509_obj = PKI.build_x509_object(certificate)
        if selector not in valid_selectors:
            raise ValueError("Invalid selector.")
        if sha not in valid_hashing_algos:
            raise ValueError("Invalid sha.")
        if selector == 0:
            hashable = PKI.serialize_cert(x509_obj, "DER")
        elif selector == 1:
            hashable = PKI.serialize_cert(x509_obj, "RPK_DER")
        hash = valid_hashing_algos[sha](hashable).hexdigest()
        return hash

    @classmethod
    def get_first_leaf_certificate(cls, dnsname, nsaddr=None, dns_timeout=5):
        """Return the first leaf certificate from TLSA records at ``dnsname``.

        This method essentially wraps
        :func:`~dane_discovery.DANE.get_tlsa_records`, and returns the first
        TLSA record with ``certificate_usage`` equal to ``1``, ``3``, or ``4``
        and ``matching_type`` of ``0``.

        Args:
            dnsname (str): DNS name to query for certificate.
            nsaddr (str): Override system resolver.
            dns_timeout (int): Timeout in seconds for DNS query.

        Return:
            dict: Dictionary with keys for ``certificate_usage``, ``selector``,
                ``matching_type``, ``certificate_association``.
                If no leaf certificate is found, None is returned.
        """
        all_tlsa_records = cls.get_tlsa_records(dnsname, nsaddr=nsaddr, dns_timeout=dns_timeout)
        for tlsa in all_tlsa_records:
            if (tlsa["certificate_usage"] in [1, 3, 4]
                    and tlsa["matching_type"] == 0):
                return tlsa

    @classmethod
    def get_tlsa_records(cls, dnsname, nsaddr=None, dns_timeout=5):
        """TLSA records in a list of dictionaries.

        This method retrieves and parses the TLSA records from
        DNS for a given DNS name.

        Args:
            dnsname (str): DNS name to query for TLSA record.
            nsaddr (str): Nameserver address.
            dns_timeout (int): Timeout in seconds for DNS query.

        Return:
            list of dict: Dictionaries with the following keys:
                ``certificate_usage``, ``selector``, ``matching_type``,
                ``certificate_association``, ``dnssec``, ``tls``, ``tcp``.
        """
        results = []
        try:
            query_details = cls.get_responses(dnsname, "TLSA", nsaddr)
            responses = query_details["responses"]
        except dns.exception.DNSException as err:
            msg = "Caught error '{}' when retrieving TLSA record.".format(err)
            raise TLSAError(msg)
        if not responses:
            raise TLSAError("No TLSA records for {}".format(dnsname))
        resp_counter = 0
        for response in responses:
            resp_counter += 1
            result = cls.process_response(response)
            # If the payload is actually a certificate, confirm that it parses.
            if result["matching_type"] == 0:
                cert = result["certificate_association"]
                PKI.validate_certificate_association(cert)
            for ctx in ["dnssec", "tcp", "tls"]:
                result[ctx] = query_details[ctx]
            results.append(result.copy())
        return results

    @classmethod
    def get_responses(cls, dnsname, rr_type, nsaddr=None, dns_timeout=5):
        """Return a list of dicts containing DNS RRs and security context.

        Args:
            dnsname (str): DNS name for query.
            rr_type (str): RR type to query. Defaults to TLSA.
            nsaddr (str): Nameserver override address.
            dns_timeout (int): Timeout in seconds for DNS query.

        Return:
            dict: Keys are ``responses`` (list of string),
                ``dnssec`` (bool), ``tls`` (bool), ``tcp`` (bool).
        """
        default_resolver = dns.resolver.get_default_resolver().nameservers[0]
        resolver = nsaddr if nsaddr else default_resolver
        query = dns.message.make_query(dnsname, rr_type, want_dnssec=True)
        query_details = {"tls": False, "dnssec": False}
        try:
            resp_msg = dns.query.tls(query, resolver, timeout=dns_timeout)
            query_details["tls"] = True
            query_details["tcp"] = True
        except ConnectionRefusedError:
            resp_msg, was_tcp = dns.query.udp_with_fallback(query, resolver,
                                                            timeout=dns_timeout)
            query_details["tcp"] = True if was_tcp else False
        flags_int = resp_msg.flags
        flags = dns.flags.to_text(flags_int)
        query_details["dnssec"] = True if "AD" in flags.split() else False
        answer = resp_msg.answer
        # Parse out RRSIGs and such- we only want the exact RR types we initially requested.
        query_details["responses"] = [a.to_text() for a in answer 
                                      if rr_type in a.to_text().split(" ")[3]]
        return query_details

    @classmethod
    def get_a_record(cls, dnsname, nsaddr=None, dns_timeout=5):
        """Get the first A record."""
        resolver = Resolver()
        if nsaddr:
            resolver.nameservers = [nsaddr]
        try:
            canonical_name = resolver.canonical_name(dnsname)
            ip_address = str(resolver.resolve(canonical_name, "A")[0])
        except dns.exception.DNSException as err:
            msg = "Caught error '{}' when retrieving A record.".format(err)
            raise ValueError(msg)
        except IndexError:
            raise ValueError("No A records for {}".format(dnsname))
        return ip_address

    @classmethod
    def process_response(cls, response):
        """Return the TLSA record, parsed into a dictionary.

        Args:
            response (str): Response from DNS query.

        Return:
            dict with keys for ``name``, ``ttl``, ``class``, 
                ``type``, ``certificate_usage``, ``selector``,
                ``matching_types``, ``certificate_association``.
        """
        result = {}
        
        resp_list = response.split(" ")
        result["name"] = resp_list.pop(0)
        result["ttl"] = int(resp_list.pop(0))
        result["class"] = resp_list.pop(0)
        result["type"] = resp_list.pop(0)
        result["certificate_usage"] = int(resp_list.pop(0))
        result["selector"] = int(resp_list.pop(0))
        result["matching_type"] = int(resp_list.pop(0))
        result["certificate_association"] = "".join(resp_list).replace(" ", "")
        cls.validate_tlsa_fields(result)
        return result

    @classmethod
    def validate_tlsa_fields(cls, tlsa_fields):
        """Validate the fields that come from DNS.

        Args:
            tlsa_fields (dict): Must contain the following keys:
                ``certificate_usage``, ``selector``, ``matching_type``, 
                ``certificate_association``.

        Return:
            None
            
        Raises:
            TLSAError if record is malformed.
        """
        issues = []
        if int(tlsa_fields["certificate_usage"]) not in [0, 1, 2, 3, 4]:
            issues.append("invalid certificate usage value")
        if int(tlsa_fields["selector"]) not in [0, 1]:
            issues.append("invalid selector value")
        if int(tlsa_fields["matching_type"]) not in [0, 1, 2]:
            issues.append("invalid matching type value")
        if not re.match("^[A-Za-z0-9]+$", tlsa_fields["certificate_association"]):
            issues.append("invalid certificate association value")
        if int(tlsa_fields["matching_type"]) == 0:
            try:
                PKI.validate_certificate_association(tlsa_fields["certificate_association"])
            except TLSAError as err:
                issues.append(str(err))
        if issues:
            raise TLSAError("Malformed DNS record: {}.".format(", ".join(issues)))

    @classmethod
    def authenticate_tlsa(cls, dns_name, record, nsaddr=None, dns_timeout=5):
        """Return None if the identity is authenticated, or raise ValueError.

        This method authenticates a TLSA record as follows:

        Any record with a certificate usage of 0-4, which is 
        correctly-formatted and delivered with DNSSEC will 
        pass authentication.

        Any record delivered without DNSSEC must have:
        ``certificate_usage`` = ``4``, ``selector`` = ``0``,
        and ``matching_type`` = ``0``. Additionally, the 
        ``certificate_association`` field must contain a certificate
        which bears a signature which can be authenticated by the 
        certificate found at 
        ``https://${IDTYPE}.${DOMAIN}/ca/${AKI}.pem``. The
        ``IDTYPE`` and ``DOMAIN`` variables are extracted from the 
        entity's DNS name, and the ``AKI`` is extracted from the 
        TLSA record's ``certificate_associattion`` field.

        Any TLSA RRs having ``certificate_usage`` == ``4`` must only have
        ``selector`` == ``0`` and ``matching_type`` == ``0``. Any deviation
        will cause validation failure.

        Args:
            dns_name (str): DNS name associated with the TLSA record.
            record (dict): Keys for ``certificate_usage``, ``selector``, 
                ``matching_type``, ``certificate_association``, 
                and ``dnssec``.
            nsaddr (str): Name server override.
            dns_timeout (int): Timeout in seconds for DNS query.
        
        Return:
            None if this identity can be cryptographically authenticated.

        Raise:
            TLSAError if the identity can not be cryptographically authenticated.
        """
        if record["dnssec"] is True:
            return
        errmsg = ""
        c_usg = record["certificate_usage"]
        if c_usg != 4:
            errmsg += "{} identity represented without DNSSEC, unable to validate.\n".format(c_usg)
        # Only certificates delivered without DNSSEC and with PKIX-CD udage set make it this far.
        if record["selector"] != 0:
            errmsg += "{} identity only permits a 'selector value' of 0.\n".format(c_usg)
        if record["matching_type"] != 0:
            errmsg += "{} identity only permits a 'matching type' value of 0.\n".format(c_usg)
        # Stop validating here if we don't have valid metadata for PKIX-CD.
        if errmsg:
            raise TLSAError(errmsg)
        certificate_association = record["certificate_association"]
        certificate_der = PKI.certificate_association_to_der(certificate_association)
        id_cert = PKI.der_to_pem(certificate_der)
        try:
            # print("Load CA cert")
            ca_certs = cls.get_ca_certificates_for_identity(dns_name, id_cert, nsaddr=nsaddr)
            # print("Test cert sig.")
            pkix_valid, reason = PKI.validate_certificate_chain(id_cert, ca_certs)
            if not pkix_valid:
                errmsg += "PKIX signature validation for identity failed: {}.\n".format(reason)
            # print("verify DNS name")
            if not PKI.verify_dnsname(dns_name, certificate_der):
                errmsg += "DNS name match against SAN failed.\n"
        except TLSAError as err:
            errmsg += "Failed to get certificate for identity: {}\n".format(err)
        if errmsg:
            raise TLSAError(errmsg)
        return

    @classmethod
    def generate_authority_hostname(cls, identity_name):
        """Return the hostname for an entity's authority server.
        
        This assumes the first underscore label found while
        parsing from TLD toward hostname ( ``._device.``
        for devices, or ``._service.``, or ``._whatever.``) 
        to be the anchor label for constructing the URL 
        where we expect to find the signing certificate.

        Args:
            identity_name (str): DNS name of identity.
        
        Raise:
            ValueError if no underscore label in ``identity_name``.

        Return:
            Authority server hostname.
        """
        # DNS name to labels
        authority_dns_labels = []
        identity_labels = identity_name.split(".")
        identity_labels.reverse()
        identity_type_label = ""
        # Build DNS name from right to left, stopping at underscore label.
        for label in identity_labels:
            if label.startswith("_"):
                identity_type_label = label.replace("_", "")
                authority_dns_labels.append(identity_type_label)
                break
            else:
                authority_dns_labels.append(label)
        if not identity_type_label:
            raise ValueError("Malformed identity name {}.".format(identity_name))
        authority_dns_labels.reverse()
        authority_hostname = ".".join(authority_dns_labels)
        return authority_hostname

    @classmethod
    def generate_url_for_ca_certificate(cls, authority_hostname, authority_key_id):
        """Return a URL for the identity's ca certificate.

        An identity conforming to DANE PKIX-CD must have
        the signing CA certificate available at a known 
        location in DNS, relative to the identity itself.

        The URL is composed from the authority server's 
        hostname and the authorityKeyId from the certificate
        that's being authenticated.

        Args:
            identity_hostname (str): DNS name of the identity.
            authority_key_id (str): AuthorityKeyId from entity certificate.
                    
        Return: 
            str: URL where a CA certificate should be found.
        """
        path = ".well-known/ca/{}.pem".format(authority_key_id)
        authority_url = urllib.parse.urlunsplit(["https", authority_hostname, path, "", ""])
        return authority_url

    @classmethod
    def get_ca_certificates_for_identity(cls, identity_name, certificate, max_levels=100, nsaddr=None, dns_timeout=5):
        """Return the CA certificates for verifying identity_name.
        
        Returns the PEM representation of the CA certificates
        used for verifying any DANE PKIX-CD certificate 
        associated with ``identity_name``.

        Args:
            identity_name (str): DNS name of identity.
            certificate (str): Certificate in PEM or DER format.
            max_levels (int): Only retrieve this many parent certificates.
            dns_timeout (int): Timeout in seconds for DNS query.

        Raise:
            ValueError if no CA certificate is found or the
                certificate is not parseable.

        Return:
            list: CA certificates which authenticate identity certificate.
        """
        ca_certs = []
        authority_hostname = cls.generate_authority_hostname(identity_name)
        current_cert = PKI.serialize_cert(PKI.build_x509_object(certificate), "PEM")
        while True:
            try:
                parent_ski = PKI.get_authority_key_id_from_certificate(current_cert)
            except ValueError as err:
                print("ValueError when parsing AKI from {}: ".format(current_cert, err))
                raise err
            ca_certificate_url = cls.generate_url_for_ca_certificate(authority_hostname, parent_ski)
            presumed_pem = cls.wrap_requests(ca_certificate_url, nsaddr)
            if not presumed_pem:
                raise ValueError("CA certificate not found at {}".format(ca_certificate_url))
            # The following line raises ValueError if it fails to parse.
            pem = PKI.serialize_cert(PKI.build_x509_object(presumed_pem), "PEM")
            ca_certs.append(pem)
            current_cert = pem
            # This catches self-signed certs.
            ski = PKI.get_subject_key_id_from_certificate(pem)
            aki = PKI.get_authority_key_id_from_certificate(pem)
            if ski == aki:
                # print("Found root cert, breaking!")
                break
            if len(ca_certs) >= max_levels:
                print("Max iterations reached ({}), breaking!".format(max_levels))
                break
        return ca_certs
    
    @classmethod
    def wrap_requests(cls, url, nsaddr=None, dns_timeout=5):
        """Wrap requests for nameserver override."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        ip_address = cls.get_a_record(hostname, nsaddr, dns_timeout)
        session = requests.Session()
        session.mount(url, ForcedIPHTTPSAdapter(dest_ip=ip_address))
        r = session.get(url, headers={"Host": hostname})
        return r.content

    @classmethod
    def get_ca_certificate_for_identity(cls, identity_name, certificate):
        """Return the CA certificate for verifying identity_name.
        
        DEPRECATED. USE `get_ca_certificates_for_identity`

        Returns the PEM representation of the CA certificate
        used for verifying any DANE PKIX-CD certificate 
        associated with ``identity_name``.

        Args:
            identity_name (str): DNS name of identity.
            certificate (str): Certificate in PEM or DER format.

        Raise:
            ValueError if no CA certificate is found or the
                certificate is not parseable.

        Return:
            str: PEM of CA signing certificate.
        """
        authority_hostname = cls.generate_authority_hostname(identity_name)
        try:
            authority_key_id = PKI.get_authority_key_id_from_certificate(certificate)
            ca_certificate_url = cls.generate_url_for_ca_certificate(authority_hostname, authority_key_id)
            r = requests.get(ca_certificate_url)
            if not r:
                raise ValueError("CA certificate not found at {}".format(ca_certificate_url))
            # The following line raises ValueError if it fails to parse.
            x509.load_pem_x509_certificate(r.content, default_backend())
            return r.content
        except requests.exceptions.RequestException as err:
            msg = "Error making request: {}".format(err)
            raise ValueError(msg)
        except x509.extensions.ExtensionNotFound as err:
            msg = "Unable to retrieve the authorityKeyID from the certificate."
            raise ValueError(msg)

    @classmethod
    def process_tlsa(cls, tlsa_record):
        """Return a dictionary describing the TLSA record's contents.

        Args:
            tlsa_record (dict): Dictionary describing TLSA record contents.

        Dictionary keys:

            ``tlsa_fields``: TLSA record parsed into a list.
        
            ``tlsa_parsed``: A dictionary of parsed TLSA record fields.
        
            ``certificate_usage``: Text description of the TLSA field.
        
            ``matching_type``: Text description of the TLSA field.
        
            ``selector``: Text description of the TLSA field.
        
            ``certificate_metadata``: Metadata parsed from the certificate.
        
            ``public_key_object``: If the TLSA record contains a public key,
            this will be the same object as generated by
            cryptography.hazmat.primitives.serialization.load_der_public_key()
        
            ``certificate_object``: If the TLSA record contains a certificate,
            this will be a cryptography.x509.Certificate object.
        """
        tlsa_fields = ["certificate_usage", "selector",
                       "matching_type", "certificate_association"]
        cert_association = tlsa_record["certificate_association"]
        cert_der = PKI.certificate_association_to_der(cert_association)
        retval = {"certificate_metadata": None, "public_key_object": None}
        retval["tlsa_fields"] = [tlsa_record[x] for x in tlsa_fields]
        retval["tlsa_parsed"] = tlsa_record.copy()
        for target in ["certificate_usage", "matching_type", "selector"]:
            retval[target] = cls.descr[target][int(tlsa_record[target])]
        if tlsa_record["matching_type"] == 0:
            retval["certificate_metadata"] = PKI.get_cert_meta(cert_der)
            retval["certificate_object"] = PKI.build_x509_object(cert_der)
            retval["public_key_object"] = retval["certificate_object"].public_key()
        return retval

