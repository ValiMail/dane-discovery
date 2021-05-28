"""Identity abstraction."""
import pprint
import urllib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
# import requests

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
        self.dnssec = False
        self.tls = False
        self.tcp = False
        self.private_key = self.load_private_key(private_key)
        self.resolver_override = resolver_override
        self.dane_credentials = []
        self.set_dane_credentials(self.dnsname, self.resolver_override)

    def validate_certificate(self, certificate):
        """Validate certificate against DANE identity records in DNS.
        
        This method returns two valufes, success and status.

        This method only checks against TLSA records with
        certificate_usage 4, or PKIX-CD.
        
        Args:
            certificate (str): Certificate in PEM or DER format.
        
        Returns:
            bool: True if successful, False if validation fails.
            str: Status indicating why validation passed or failed.
        """
        cert_obj = DANE.build_x509_object(certificate)
        why_not = []
        default = "Unable to find a TLSA record with certificate usage 4."
        # For each TLSA certificate, attempt to validate local cert.
        for credential in self.dane_credentials:
            valid = False
            cert_usage = credential["certificate_usage"]
            if cert_usage == "PKIX-CD":
                valid, reason = self.validate_pkix_cd(cert_obj, credential)
                if valid:
                    return True, reason
                else:
                    why_not.append(reason)
        if not why_not:
            why_not.append(default)
        return False, "\n".join(why_not)

    def validate_pkix_cd(self, cert_obj, credential):
        """Validate a certificate with certificate_usage 4.
        
        PKIX-CD expects selector 0 and matching type 0. This
        method will not validate configuration which differs 
        from this expectation.

        Args:
            cert_obj (cryptography.x509): Certificate object.
            credential (dict): Parsed credential from DNS.

        Returns:
            bool: True or False for validation
            string: Reason for validation pass/fail.
        """
        why_not = []
        # Check TLSA records for wrong selector and matching type.
        selector = credential["tlsa_parsed"]["selector"]
        matching_type = credential["tlsa_parsed"]["matching_type"]
        if selector != 0:
            why_not.append("Selector set to {}.".format(selector))
        if matching_type != 0:
            why_not.append("Matching type set to {}.".format(matching_type))
        if why_not:
            return False, "\n".join(why_not)
        # Check to see that the DER matches what's in DNS
        cert_der = cert_obj.public_bytes(encoding=serialization.Encoding.DER)
        cert_association = credential["tlsa_parsed"]["certificate_association"]
        tlsa_der = DANE.certificate_association_to_der(cert_association)
        if not cert_der == tlsa_der:
            return False, "Certificate and TLSA certificate association do nt match."
        # Get the CA certificate
        try:
            ca_pem = DANE.get_ca_certificate_for_identity(self.dnsname, cert_der)
        except ValueError as err:
            return False, str(err)
        ca_validation = DANE.verify_certificate_signature(cert_der, ca_pem)
        if not ca_validation:
            return False, "Validation against CA certificate failed."
        return True, "Format and authority CA signature verified."

    def get_first_entity_certificate(self, strict=True):
        """Return the first entity certificate for the identity.

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
            cryptography.x509.Certificate: Certificate object as parsed 
                from TLSA record.
        """
        supported_certificate_types = {"PKIX-EE": 1, "DANE-EE": 3, "PKIX-CD": 4}
        target = ""
        # Find a matching credential
        for cred in self.dane_credentials:
            if not cred["tlsa_parsed"]["matching_type"] == 0:
                continue
            target = cred if cred["tlsa_parsed"]["certificate_usage"] in [1, 3, 4] else ""
            if target:
                break
        if not target:
            raise TLSAError("No entity certificate found for {}.".format(self.dnsname))
        if strict:
            try:
                target["tlsa_parsed"]["dnssec"] = self.dnssec
                DANE.authenticate_tlsa(self.dnsname, target["tlsa_parsed"])
            except ValueError as err:
                raise TLSAError(err)
        return target["certificate_object"]


    def get_first_entity_certificate_by_type(self, cert_type, strict=True):
        """Return the first certificate of ``cert_type`` for the identity.
        
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
            cryptography.x509.Certificate: Certificate object as parsed 
                from TLSA record.
        """
        supported_certificate_types = {"PKIX-EE": 1, "DANE-EE": 3, "PKIX-CD": 4}
        target = ""
        # Verify that we're asked for something legitimate
        if cert_type not in supported_certificate_types:
            raise ValueError("Unsupported cert type {}".format(cert_type))
        type_id = supported_certificate_types[cert_type]
        # Find a matching credential
        for cred in self.dane_credentials:
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
        return target["certificate_object"]

    def report(self):
        """Return a report for the identity.

        Prints the query context (DNSSEC, etc) as well as information about
        the TLSA records stored at the identity's name.
        """
        fmt = "Name: {}\n".format(self.dnsname)
        fmt += ("Request context:\n DNSSEC: {}\n TLS: {}\n "
                "TCP: {}\n".format(self.dnssec, self.tls, self.tcp))
        cred_index = 0
        fmt += ("Public credentials: {}\n".format(len(self.dane_credentials)))
        for cert in self.dane_credentials:
            validation_err = ""
            cert["tlsa_parsed"]["dnssec"] = self.dnssec
            try:
                DANE.authenticate_tlsa(self.dnsname, cert["tlsa_parsed"])
            except ValueError as err:
                validation_err = "\n        ".join(["    {}".format(x) for x in str(err).splitlines()])
            validation_status = ("\n    Cryptographically validated." 
                                 if not validation_err 
                                 else "\n  Not validated:\n{}".format(validation_err))
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
        
            ``certificate_object``: If the TLSA record conatins a certificate,
            this will be a cryptography.x509.Certificate object.
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
            retval["certificate_object"] = DANE.build_x509_object(cert_der)
            retval["public_key_object"] = retval["certificate_object"].public_key()
        return retval

    def get_all_certificates(self, filters=[]):
        """Return a dictionary of all PKIX-CD certificates for this identity.

        This method uses available methods for validating certificates retrieved
        from TLSA records associated with the identity's DNS name. 
        
        For DANE-EE, we really just care that it parses and it was delivered with 
        DNSSEC. 
        
        For PKIX-EE, we require delivery to be protected by DNSSEC. In the future,
        when the Python cryptography library supports full PKIX validation, we will
        also include PKIX validation. https://github.com/pyca/cryptography/issues/2381

        For PKIX-CD, we require that the trust chain be represented out-of-band in 
        accordance with the proposed standard for certificate and trust chain discovery.

        Keyword args:
            filters (list): List of filters for specific DANE certificate usages.
                Valid filters are: "DANE-EE", "PKIX-EE", "PKIX-CD".

        Return: 
            dict: Dictionary key is ``${DNSNAME}-${CERTHASH}``, and the value is the
                the PEM-encoded certificate.
        """
        retval = {}
        # Bail if a bad filter is used.
        if filters:
            for filter_val in filters:
                if filter_val not in ["DANE-EE", "PKIX-EE", "PKIX-CD"]:
                    raise ValueError("Invalid filter: {}".format(filter_val))
        else:
            filters = ["DANE-EE", "PKIX-EE", "PKIX-CD"]
        # Iterate and authenticate
        for cred in self.dane_credentials:
            tlsa = cred["tlsa_parsed"]
            # If it's not a full cert, skip
            if not tlsa["matching_type"] == 0:
                continue
            id_name = self.dnsname 
            cert_obj = cred["certificate_object"]
            cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
            cert_hash = DANE.generate_sha_by_selector(cert_pem, "sha256", 0)
            # Validate for PKIX-CD
            if (tlsa["certificate_usage"] == 4 and "PKIX-CD" in filters):
                valid, _ = self.validate_pkix_cd(cert_obj, cred)
                if not valid:
                    continue
                retval["{}-{}".format(id_name, cert_hash)] = cert_pem
            # Validate for DANE-EE (delivered via DNSSEC?)
            if (tlsa["certificate_usage"] == 3 and "DANE-EE" in filters):
                if not self.dnssec:
                    continue
                retval["{}-{}".format(id_name, cert_hash)] = cert_pem
            # Validate for PKIX-EE (delivered via DNSSEC?)
            if (tlsa["certificate_usage"] == 1 and "PKIX-EE" in filters):
                if not self.dnssec:
                    continue
                retval["{}-{}".format(id_name, cert_hash)] = cert_pem
        return retval


    def set_dane_credentials(self, dnsname, resolver_override):
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

    