"""DANE class definition."""
import binascii
import hashlib
import requests
import urllib

import dns.resolver
import dns.dnssec
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm

from .exceptions import TLSAError


class DANE:
    """Abstract interactions involved in certificate retrieval."""

    @classmethod
    def build_x509_object(cls, certificate):
        """Wrap format determination and return an x509 object.

        Args:
            certificate (str): Certificate in PEM or DER format.

        Return:
            cryptography.x509.Certificate object.

        Raise:
            TLSAError if unable to parse.
        """
        if isinstance(certificate, str):
            certificate = certificate.encode()
        try:
            return x509.load_pem_x509_certificate(certificate,
                                                  default_backend())
        except ValueError:  # This hits if it's a DER cert.
            pass
        return x509.load_der_x509_certificate(certificate,
                                              default_backend())

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
        x509_obj = cls.build_x509_object(certificate)
        cert_bytes = x509_obj.public_bytes(encoding=serialization.Encoding.DER)
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
        x509_obj = cls.build_x509_object(certificate)
        if selector not in valid_selectors:
            raise ValueError("Invalid selector.")
        if sha not in valid_hashing_algos:
            raise ValueError("Invalid sha.")
        if selector == 0:
            hashable = x509_obj.public_bytes(serialization.Encoding.DER)
        elif selector == 1:
            pubkey = x509_obj.public_key()
            hashable = pubkey.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)  # NOQA
        hash = valid_hashing_algos[sha](hashable).hexdigest()
        return hash

    @classmethod
    def get_first_leaf_certificate(cls, dnsname):
        """Return the first leaf certificate from TLSA records at ``dnsname``.

        This method essentially wraps
        :func:`~dane_discovery.DANE.get_tlsa_records`, and returns the first
        TLSA record with ``certificate_usage`` equal to ``1``, ``3``, or ``4``
        and ``matching_type`` of ``0``.

        Args:
            dnsname (str): DNS name to query for certificate.

        Return:
            dict: Dictionary with keys for ``certificate_usage``, ``selector``,
                ``matching_type``, ``certificate_association``.
                If no leaf certificate is found, None is returned.
        """
        all_tlsa_records = cls.get_tlsa_records(dnsname)
        for tlsa in all_tlsa_records:
            if (tlsa["certificate_usage"] in [1, 3, 4]
                    and tlsa["matching_type"] == 0):
                return tlsa

    @classmethod
    def get_tlsa_records(cls, dnsname, nsaddr=None):
        """TLSA records in a list of dictionaries.

        This method retrieves and parses the TLSA records from
        DNS for a given DNS name.

        Args:
            dnsname (str): DNS name to query for TLSA record.
            nsaddr (str): Nameserver address.

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
                cls.validate_certificate(cert)
            for ctx in ["dnssec", "tcp", "tls"]:
                result[ctx] = query_details[ctx]
            results.append(result.copy())
        return results

    @classmethod
    def get_responses(cls, dnsname, rr_type, nsaddr=None):
        """Return a list of dicts containing DNS RRs and security context.

        Args:
            dnsname (str): DNS name for query.
            rr_type (str): RR type to query. Defaults to TLSA.

        Return:
            dict: Keys are ``responses`` (list of string),
                ``dnssec`` (bool), ``tls`` (bool), ``tcp`` (bool).
        """
        timeout = 5
        default_recursor = dns.resolver.get_default_resolver().nameservers[0]
        resolver = nsaddr if nsaddr else default_recursor
        query = dns.message.make_query(dnsname, rr_type, want_dnssec=True)
        query_details = {"tls": False, "dnssec": False}
        try:
            resp_msg = dns.query.tls(query, resolver, timeout=timeout)
            query_details["tls"] = True
            query_details["tcp"] = True
        except ConnectionRefusedError:
            resp_msg, was_tcp = dns.query.udp_with_fallback(query, resolver,
                                                            timeout=timeout)
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
    def certificate_association_to_der(cls, certificate_association):
        """Return DER bytes from a TLSA record's ``certificate_association``.

        Args:
            certificate_association (str): Certificate association information
                extracted from a TLSA record.

        Return:
            bytes: DER-formatted certificate.
        """
        return binascii.unhexlify(certificate_association)

    @classmethod
    def der_to_pem(cls, der_cert):
        """Return the PEM representation of a TLSA certificate_association.

        Args:
            der (str): A certificate in DER format.

        Return:
            bytes: PEM-formatted certificate.
        """
        cert = cls.build_x509_object(der_cert)
        return cert.public_bytes(serialization.Encoding.PEM)

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
        return result

    @classmethod
    def validate_certificate(cls, certificate):
        """Raise TLSAError if certificate does not parse, or return None.

        Args:
            certificate (str): Certificate association data from TLSA record.

        Return:
            None

        Raise:
            TLSAError if parsing fails.
        """
        try:
            der = cls.certificate_association_to_der(certificate)
            cls.build_x509_object(der)
        except (ValueError, binascii.Error) as err:
            msg = "Caught error '{}' with TLSA record.".format(err)
            raise TLSAError(msg)

    @classmethod
    def authenticate_tlsa(cls, dns_name, record):
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
        ``https://authority.${IDTYPE}.${DOMAIN}/ca/${AKI}.pem``. The
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
        certificate_der = cls.certificate_association_to_der(certificate_association)
        id_cert = cls.der_to_pem(certificate_der)
        try:
            print("Load CA cert")
            ca_cert = cls.get_ca_certificate_for_identity(dns_name, id_cert)
            print("Test cert sig.")
            if not cls.verify_certificate_signature(id_cert, ca_cert):
                errmsg += "PKIX signature validation for identity failed.\n"
            print("verify DNS name")
            if not cls.verify_dnsname(dns_name, certificate_der):
                errmsg += "DNS name match against SAN failed.\n"
        except TLSAError as err:
            errmsg += "Failed to get certificate for identity: {}\n".format(err)
        if errmsg:
            raise TLSAError(errmsg)
        return

    @classmethod
    def verify_dnsname(cls, dns_name, certificate_der):
        """Return True if the first dNSName in the SAN matches."""
        x5_obj = cls.build_x509_object(certificate_der)
        san = x5_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_names = san.value.get_values_for_type(x509.DNSName)
        if san_dns_names[0] != dns_name:
            return False
        return True
        
    
    @classmethod
    def verify_certificate_signature(cls, entity_certificate, ca_certificate):
        """ Return True if entity_certificate was signed by ca_certificate.

        Args:
            entity_certificate (str): entity certificate in DER or PEM format.
            ca_certificate (str): CA certificate in DER or PEM format.

        Return: 
            bool: True if the ca_certificate validates the entity_certificate.
        """
        issuer_public_key = DANE.build_x509_object(ca_certificate).public_key()
        cert_to_check = DANE.build_x509_object(entity_certificate)
        if isinstance(issuer_public_key, RSAPublicKey):
            try:
                issuer_public_key.verify(cert_to_check.signature,
                    cert_to_check.tbs_certificate_bytes, padding.PKCS1v15(),
                    cert_to_check.signature_hash_algorithm)
            except InvalidSignature:
                return False
        elif isinstance(issuer_public_key, EllipticCurvePublicKey):
            try:
                issuer_public_key.verify(cert_to_check.signature,
                    cert_to_check.tbs_certificate_bytes,
                    cert_to_check.signature_hash_algorithm)
            except InvalidSignature:
                return False
            except UnsupportedAlgorithm:
                return False
        else:
            raise ValueError("Unsupported public key type {}".format(type(issuer_public_key)))
        return True

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
        # Build DNS name from right to left, stopping at underscore label.
        for label in identity_labels:
            if label.startswith("_"):
                authority_dns_labels.append(label.replace("_", ""))
                authority_dns_labels.append("authority")
                break
            else:
                authority_dns_labels.append(label)
        if not authority_dns_labels[-1] == "authority":
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
        path = "ca/{}.pem".format(authority_key_id)
        authority_url = urllib.parse.urlunsplit(["https", authority_hostname, path, "", ""])
        return authority_url

    @classmethod
    def get_authority_key_id_from_certificate(cls, certificate):
        """Return the authorityKeyIdentifier for the certificate.
        
        
        Args:
            certificate (str): Certificate in PEM or DER format.
        """
        cert_obj = cls.build_x509_object(certificate)
        akid = cert_obj.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
            ).value.key_identifier
        return binascii.hexlify(akid, '-').decode()

    @classmethod
    def get_subject_key_id_from_certificate(cls, certificate):
        """Return the subjectKeyIdentifier for the certificate.
        
        
        Args:
            certificate (str): Certificate in PEM or DER format.
        """
        cert_obj = cls.build_x509_object(certificate)
        skid = x509.SubjectKeyIdentifier.from_public_key(cert_obj.public_key())
        return binascii.hexlify(skid.digest, '-').decode()

    @classmethod
    def get_ca_certificate_for_identity(cls, identity_name, certificate):
        """Return the CA certificate for verifying identity_name.
        
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
            authority_key_id = cls.get_authority_key_id_from_certificate(certificate)
            ca_certificate_url = cls.generate_url_for_ca_certificate(authority_hostname, authority_key_id)
            r = requests.get(ca_certificate_url)
            presumed_pem = r.content
            if not r:
                raise ValueError("CA certificate not found at {}".format(ca_certificate_url))
            # The following line raises ValueError if it fails to parse.
            x509.load_pem_x509_certificate(presumed_pem, default_backend())
            return presumed_pem
        except requests.exceptions.RequestException as err:
            msg = "Error making request: {}".format(err)
            raise ValueError(msg)
        except x509.extensions.ExtensionNotFound as err:
            msg = "Unable to retrieve the authorityKeyID from the certificate."
            raise ValueError(msg)



