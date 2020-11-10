"""Identity abstraction."""
import pprint
import urllib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import requests

from .dane import DANE
from .exceptions import TLSAError


class Identity:
    """Represent a DANE identity."""

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

    def __init__(self, dnsname, private_key=None, resolver_override=None):
        """Initialize with the DNS name.

        Args:
            dnsname (str): DNS name of identity.
            private_key (str): Private key in PEM format. Optional.
            resolver_override (str): Override the default resolver IP address.

        Raise:
            TLSAError if identity does not exist in DNS.
        """
        self.dnsname = dnsname
        self.private_key = self.load_private_key(private_key)
        self.resolver_override = resolver_override
        self.public_credentials = []
        self.set_public_credentials(self.dnsname, self.resolver_override)

    def get_first_entity_certificate_by_type(self, cert_type, strict=False):
        """Return the first certificate of ``cert_type` for the identity.
        
        Supported certificate types:
            PKIX-EE: Corresponds with ``certificate_usage`` ``1``.
            DANE-EE: Corresponds with ``certificate_usage`` ``3``.
            PKIX-CD: Corresponds with ``certificate_usage`` ``4``.


        Keyword args:
            strict (bool): Raise TLSAError if certificate was not retrieved
                with the benefit of DNSSEC, or in the case of PKIX-CD, if the
                certificate can not be validated via PKI.
        
        Raise:
            TLSAError: If strict is set to ``True`` and the certificate cannot
                be validated by carrying a DNSSEC RRSIG. If ``certificate_usage`` 
                is set to ``4``, PKIX validation may be attempted in lieu of 
                DNSSEC.
            ValueError: If ``cert_type`` is unsupported.
        
        Return:
            str: PEM representation of a certificate matching the query criteria,
                or an empty string if none can be found.
        """
        supported_certificate_types = {"PKIX-EE": 1, "DANE-EE": 3, "PKIX-CD": 4}
        target = ""
        # Verify that we're asked for something legitimate
        if cert_type not in supported_certificate_types:
            raise ValueError("Unsupported cert type {}".format(cert_type))
        type_id = supported_certificate_types[cert_type]
        # Find a matching credential
        for cred in self.public_credentials:
            if not cred["tlsa_parsed"]["matching_type"] == 0:
                continue
            target = cred if cred["tlsa_parsed"]["certificate_usage"] == type_id else ""
            if target:
                break
        if not target:
            return ""
        if strict:
            try:
                target["tlsa_parsed"]["dnssec"] = self.dnssec
                DANE.authenticate_tlsa(self.dnsname, target["tlsa_parsed"])
            except ValueError as err:
                raise TLSAError(err)
        return target["public_key_object"]

    def report(self):
        """Return a report for the identity.

        Prints the query context (DNSSEC, etc) as well as information about
        the TLSA records stored at the identity's name.
        """
        fmt = "Name: {}\n".format(self.dnsname)
        fmt += ("Request context:\n DNSSEC: {}\n TLS: {}\n "
                "TCP: {}\n".format(self.dnssec, self.tls, self.tcp))
        cred_index = 0
        for cert in self.public_credentials:
            validation_err = ""
            cert["dnssec"] = self.dnssec
            try:
                DANE.authenticate_tlsa(self.dnsname, cert)
            except ValueError as err:
                validation_err = ["    {}".format(x) for x in str(err).splitlines()]
                validation_err = "\n".join(validation_err)
            validation_status = ("\n    Cryptographically validated." 
                                 if not validation_err 
                                 else "\n{}".format(validation_err))
            fmt += ("Credential index: {}\n"
                    "validation status: {} \n"
                    " certificate usage: {}\n"
                    " selector: {}\n"
                    " matching type: {}\n".format(cred_index,
                                                  validation_status,
                                                  cert["certificate_usage"],
                                                  cert["selector"],
                                                  cert["matching_type"]))
            if "certificate_metadata" in cert:
                attributes = pprint.pformat(cert["certificate_metadata"])
                fmt += (" x509 attributes:\n")
                for attribute in attributes.splitlines():
                    fmt += ("    {}\n".format(attribute))
            fmt += "----------"
            fmt += "\n"
        return fmt

    @classmethod
    def get_cert_meta(cls, cert_der):
        """Return a dictionary containing certificate metadata."""
        retval = {"subject": {}, "extensions": {}}
        x509_obj = DANE.build_x509_object(cert_der)
        for item in x509_obj.subject:
            retval["subject"][item.oid._name] = item.value
        for extension in x509_obj.extensions:
            xtn = cls.parse_extension(extension)
            xtn_name = [x for x in xtn.keys()][0]
            retval["extensions"][xtn_name] = xtn[xtn_name]
        return retval

    @classmethod
    def parse_extension(cls, x509_ext):
        """Return a dictionary representation of the x509 extension."""
        usage = ["content_commitment", "crl_sign", "data_encipherment",
                 "digital_signature", "key_agreement", "key_cert_sign",
                 "key_encipherment"]
        oidname = x509_ext.oid._name
        if oidname == "basicConstraints":
            return {"BasicConstraints": {"ca": x509_ext.value.ca,
                                        "path_length":
                                        x509_ext.value.path_length}}
        elif oidname == "extendedKeyUsage":
            return {"ExtendedKeyUsage": [oid._name for oid
                                         in x509_ext.value]}
        elif oidname == "subjectAltName":
            return {"SubjectAltName": [oid.value for oid in x509_ext.value]}
        elif oidname == "keyUsage":
            return {"KeyUsage": {x: getattr(x509_ext.value, x) for x in usage}}
        return {x509_ext.oid._name: x509_ext.value}

    @classmethod
    def load_private_key(cls, private_key):
        """Return a private key.

        Wraps cryptography.hazmat.primitives.serialization.load_pem_private_key
        and returns the appropriate type.

        Args:
            private_key (str): Private key in PEM format.

        Return:
            Private key object, or None if ``private_key`` arg is None.

        Raise:
            ValueError if there's an error loading the key.
        """
        if private_key is None:
            return None
        return serialization.load_pem_private_key(private_key, password=None)

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
        """
        tlsa_fields = ["certificate_usage", "selector",
                       "matching_type", "certificate_association"]
        cert_association = tlsa_record["certificate_association"]
        cert_der = DANE.certificate_association_to_der(cert_association)
        retval = {"certificate_metadata": None, "public_key_object": None}
        retval["tlsa_fields"] = [tlsa_record[x] for x in tlsa_fields]
        retval["tlsa_parsed"] = tlsa_record.copy()
        for target in ["certificate_usage", "matching_type", "selector"]:
            retval[target] = cls.descr[target][int(tlsa_record[target])]
        if tlsa_record["matching_type"] == 0:
            retval["certificate_metadata"] = cls.get_cert_meta(cert_der)
            x509_obj = DANE.build_x509_object(cert_der)
            retval["public_key_object"] = x509_obj.public_key()
        return retval

    def set_public_credentials(self, dnsname, resolver_override):
        """Get public credentials from DNS and set DNS retrieval context.

        Args:
            dnsname (str): Name of DNS-based identity.
            resolver_override (str): Optional. Override the default resolver
                IP address.
        """
        tlsa_records = DANE.get_tlsa_records(dnsname, resolver_override)
        request_context_fields = ["dnssec", "tcp", "tls"]
        for field in request_context_fields:
            setattr(self, field, tlsa_records[0][field])
        self.dane_credentials = [self.process_tlsa(record) for record
                                 in tlsa_records]

    