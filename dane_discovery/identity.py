"""Identity abstraction."""
import pprint

from cryptography.hazmat.primitives import serialization

from .dane import DANE
from .pki import PKI
from .exceptions import TLSAError


class Identity:
    """Represent a DANE identity."""

    def __init__(self, dnsname, private_key=None, resolver_override=None, dns_timeout=5):
        """Initialize with the DNS name.

        Args:
            dnsname (str): DNS name of identity.
            private_key (str): Private key in PEM format. Optional.
            resolver_override (str): Override the default resolver IP address.
            dns_timeout (int): Set DNS timeout.

        Raise:
            TLSAError if identity does not exist in DNS.
        """
        self.dnsname = dnsname
        self.dnssec = False
        self.tls = False
        self.tcp = False
        self.private_key = PKI.load_private_key(private_key)
        self.resolver_override = resolver_override
        self.dane_credentials = []
        self.dns_timeout = dns_timeout
        self.set_dane_credentials(self.dnsname)

    def validate_certificate(self, certificate):
        """Return True, None if the certificate is valid for the identity.
        
        This method returns two values, success and status.

        This method only checks against TLSA records with
        certificate_usage 4, or PKIX-CD.
        
        Args:
            certificate (str): Certificate in PEM or DER format.
        
        Returns:
            bool: True if successful, False if validation fails.
            str: Status indicating why validation passed or failed.
        """
        cert_obj = PKI.build_x509_object(certificate)
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
        cert_association = credential["tlsa_parsed"]["certificate_association"]
        if selector != 0:
            why_not.append("Selector set to {}.".format(selector))
        if matching_type != 0:
            why_not.append("Matching type set to {}.".format(matching_type))
        if why_not:
            return False, "\n".join(why_not)
        # Check to see that the DER matches what's in DNS
        cert_der = cert_obj.public_bytes(encoding=serialization.Encoding.DER)
        tlsa_der = PKI.certificate_association_to_der(cert_association)
        if not cert_der == tlsa_der:
            return False, "Certificate and TLSA certificate association do not match."
        # Get the CA certificate
        try:
            ca_pems = DANE.get_ca_certificates_for_identity(self.dnsname, cert_der, 100, self.resolver_override, self.dns_timeout)
        except ValueError as err:
            return False, str(err)
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        validated, reason = PKI.validate_certificate_chain(cert_pem, ca_pems)
        if not validated:
            return False, "Validation against CA certificate failed: {}.".format(reason)
        return True, "Format and authority CA signature verified."

    def get_pkix_cd_trust_chain(self, certificate, max_levels=100):
        """Return a dictionary with entire discovered trust chain.
        
        Args:
            certificate (str): EE certificate to begin trust chain discovery with.
            max_levels (int): Maximum number of parent certificates to discover. Default: 3.
        
        Returns:
            dict: Dictionary with integer keys for entity cert (``0``) and intermediate CA certificates.
                The root certificate key is ``root``.
        """
        certificate = PKI.build_x509_object(certificate).public_bytes(serialization.Encoding.PEM)
        retval = {0: certificate}
        next_level = 1
        ca_certificates = DANE.get_ca_certificates_for_identity(self.dnsname, certificate, max_levels, self.resolver_override, self.dns_timeout)
        chain_valid, reason = PKI.validate_certificate_chain(certificate, ca_certificates)
        if not chain_valid:
            raise ValueError(reason)
        for cert in ca_certificates:
            aki = PKI.get_authority_key_id_from_certificate(cert)
            ski = PKI.get_subject_key_id_from_certificate(cert)
            if aki == ski:
                # The root cert is the last, so we break here.
                retval["root"] = cert
                break
            retval[next_level] = cert
            next_level += 1
        return retval

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
                DANE.authenticate_tlsa(self.dnsname, target["tlsa_parsed"], self.resolver_override, self.dns_timeout)
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
                DANE.authenticate_tlsa(self.dnsname, target["tlsa_parsed"], self.resolver_override, self.dns_timeout)
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

    def get_all_certificates(self, filters=[]):
        """Return a dictionary of all EE certificates for this identity.

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


    def set_dane_credentials(self, dnsname):
        """Get public credentials from DNS and set DNS retrieval context.

        Args:
            dnsname (str): Name of DNS-based identity.
            resolver_override (str): Optional. Override the default resolver
                IP address.
        """
        tlsa_records = DANE.get_tlsa_records(dnsname, self.resolver_override, self.dns_timeout)
        request_context_fields = ["dnssec", "tcp", "tls"]
        for field in request_context_fields:
            setattr(self, field, tlsa_records[0][field])
        self.dane_credentials = [DANE.process_tlsa(record) for record
                                 in tlsa_records]

    def cert_matches_private_key(self, cert_obj):
        """Return boolean for alignment between private key and cert_obj, and a reason.
        
        Args:
            cert_obj (cryptography.x509): A certificate object.

        Returns:
            bool: True if the public key in the certificate matches the private key.
            str: If validation failed, why it failed.
        """
        cert_public_key = cert_obj.public_key()
        public_key_from_privkey = self.private_key.public_key()
        cert_pubkey_type = type(cert_public_key)
        privkey_pubkey_type = type(public_key_from_privkey)
        if not cert_pubkey_type == privkey_pubkey_type:
            reason = "Key type mismatch: cert: {} privkey: {}.".format(cert_pubkey_type,
                                                                       privkey_pubkey_type)
            return False, reason
        if not (cert_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) 
                == public_key_from_privkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)):
            reason = "Public key bytes mismatch."
            return False, reason
        return True, ""

    