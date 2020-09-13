"""DANE class definition."""
import binascii
import hashlib

import dns.resolver
import dns.dnssec
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

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
        try:
            return x509.load_pem_x509_certificate(certificate,
                                                  default_backend())
        except ValueError:  # This hits if it's a DER cert.
            pass
        except TypeError as err:
            raise TLSAError(err)
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
        TLSA record with ``certificate_usage`` equal to ``1`` or ``3``, and
        ``matching_type`` of ``0``.

        Args:
            dnsname (str): DNS name to query for certificate.

        Return:
            dict: Dictionary with keys for ``certificate_usage``, ``selector``,
                ``matching_type``, ``certificate_association``.
                If no leaf certificate is found, None is returned.
        """
        all_tlsa_records = cls.get_tlsa_records(dnsname)
        for tlsa in all_tlsa_records:
            if (tlsa["certificate_usage"] in [1, 3]
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
        query_details["responses"] = [a.to_text() for a in answer]
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
            dict with keys for ``certificate_usage``, ``selector``,
                ``matching_types``, ``certificate_association``.
        """
        result = {}
        resp_list = response.split(" ")
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
