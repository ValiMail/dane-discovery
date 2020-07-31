"""DANE class definition."""
import binascii

import dns.resolver
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
            errmsg = "Unsupported matching type: SHA-256."
            raise TLSAError(errmsg)
        elif matching_type == 2:
            errmsg = "Unsupported matching type: SHA-512"
            raise TLSAError(errmsg)
        else:
            err_msg = "Invalid matching type {}.".format(matching_type)
            raise TLSAError(err_msg)
        tlsa_rr = "{} {} {} {}".format(certificate_usage, selector,
                                       matching_type,
                                       certificate_association)
        return tlsa_rr

    @classmethod
    def get_tlsa_records(cls, dnsname):
        """TLSA records in a list of dictionaries.

        This method retrieves and parses the TLSA records from
        DNS for a given DNS name.

        Args:
            dnsname (str): DNS name to query for TLSA record.

        Return:
            list of dict: Dictionaries with the following keys:
                ``certificate_usage``, ``selector``, ``matching_type``,
                ``certificate``.

        Raise:
            TLSAError if any errors are encountered in retrieval or parsing.
        """
        results = []
        try:
            responses = [r.to_text() for r in
                         dns.resolver.resolve(dnsname, "TLSA")]
        except dns.resolver.NXDOMAIN as err:
            msg = "Caught error '{}' when retrieving TLSA record.".format(err)
            raise TLSAError(msg)
        except dns.resolver.NoAnswer as err:
            msg = "Caught error '{}' when retrieving TLSA record.".format(err)
            raise TLSAError(msg)
        resp_counter = 0
        for response in responses:
            print(response)
            resp_counter += 1
            result = cls.process_response(response)
            # If the payload is actually a certificate, confirm that it loads.
            if result["matching_type"] == 0:
                cert = result["certificate_association"]
                cls.validate_certificate(cert)
                result["certificate_association"] = binascii.unhexlify(cert)
            results.append(result.copy())
        return results

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
            certificate (str): Certificate.

        Return:
            None

        Raise:
            TLSAError if parsing fails.
        """
        try:
            der = binascii.unhexlify(certificate)
            cls.build_x509_object(der)
        except (ValueError, binascii.Error) as err:
            msg = "Caught error '{}' with TLSA record.".format(err)
            raise TLSAError(msg)
