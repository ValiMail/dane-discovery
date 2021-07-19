"""PKI- and Certificate-oriented utilities here."""
import binascii

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm

from .exceptions import TLSAError

class PKI:
    @classmethod
    def build_x509_object(cls, certificate):
        """Return a cryptography.x509.Certificate object.

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
            x5cert = cls.clean_up_certificate(certificate)
            return x509.load_pem_x509_certificate(x5cert,
                                                  default_backend())
        except ValueError:  # This hits if it's a DER cert.
            pass
        return x509.load_der_x509_certificate(certificate,
                                              default_backend())

    @classmethod
    def build_public_key_object_from_der(cls, der):
        """Return a Python cryptography public key object."""
        return serialization.load_der_public_key(der)

    @classmethod
    def serialize_cert(cls, certificate, fmt):
        """Return certificate bytes in the selected format.
        
        Args:
            certificate (cryptography.x509.Certificate): Certificate to parse.
            fmt (str): DER, PEM, or RPK_DER. RPK_DER is raw public key, DER encoding.
        
        Returns:
            bytes: Serialized certificate.
            
        Raises:
            ValueError if an invalid format was requested.
        """
        if fmt == "PEM":
            return certificate.public_bytes(serialization.Encoding.PEM)
        elif fmt == "DER":
            return certificate.public_bytes(serialization.Encoding.DER)
        elif fmt == "RPK_DER":
            pubkey = certificate.public_key()
            return pubkey.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
        raise ValueError("Unsupported serialization format requested.")

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
    def clean_up_certificate(cls, certificate):
        """This method returns a clean PEM-encoded certificate.
        
        This is useful for removing the human-readable certificate
        metadata that sometimes ends up in certificates produced 
        by OpenSSL.
        """
        if isinstance(certificate, bytes):
            certificate = certificate.decode("utf-8")
        in_lines = certificate.splitlines()
        out_lines = []
        for line in in_lines:
            if line.startswith(" "):
                continue
            if line.startswith("Certificate:"):
                continue
            out_lines.append(line)
        return "\n".join(out_lines).encode()

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
    def format_keyid(cls, keyid):
        """Return dash-delimited string from keyid."""
        delimiter = '-'
        hex_bytes = []
        keyid = [x for x in keyid]
        keyid.reverse()
        while keyid:
            first = keyid.pop()
            second = keyid.pop()
            hex_bytes.append("{}{}".format(first, second))
        return delimiter.join([x for x in hex_bytes])
    
    @classmethod
    def get_authority_key_id_from_certificate(cls, certificate):
        """Extract and return the authorityKeyIdentifier from the certificate.
        
        Args:
            certificate (str): Certificate in PEM or DER format.
        """
        cert_obj = cls.build_x509_object(certificate)
        akid = cert_obj.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
            ).value.key_identifier
        akid_hex = binascii.hexlify(akid).decode()
        return cls.format_keyid(akid_hex)

    @classmethod
    def get_cert_meta(cls, cert_der):
        """Return a dictionary containing certificate metadata."""
        retval = {"subject": {}, "extensions": {}}
        x509_obj = cls.build_x509_object(cert_der)
        for item in x509_obj.subject:
            retval["subject"][item.oid._name] = item.value
        for extension in x509_obj.extensions:
            xtn = cls.parse_extension(extension)
            xtn_name = [x for x in xtn.keys()][0]
            retval["extensions"][xtn_name] = xtn[xtn_name]
        return retval

    @classmethod
    def get_dnsnames_from_cert(cls, x5_obj):
        """Return the dnsnames from the certificate's SAN.

        Args:
            x5_obj (cryptography.x509): Certificate object.
        
        Return: 
            list: str: dNSNames from certificate SAN.
        """
        san = x5_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san.value.get_values_for_type(x509.DNSName)

    @classmethod
    def get_subject_key_id_from_certificate(cls, certificate):
        """Return the subjectKeyIdentifier for the certificate.

        Args:
            certificate (str): Certificate in PEM or DER format.
        """
        cert_obj = cls.build_x509_object(certificate)
        skid = x509.SubjectKeyIdentifier.from_public_key(cert_obj.public_key())
        skid_hex = binascii.hexlify(skid.digest).decode()
        return cls.format_keyid(skid_hex)

    @classmethod
    def is_a_ca_certificate(cls, certificate):
        """Return True if ``certificate`` is a CA certificate."""
        x5_obj = cls.build_x509_object(certificate)
        basic_constraints = x5_obj.extensions.get_extension_for_class(x509.BasicConstraints)
        if basic_constraints.value.ca is True:
            return True
        return False

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
    def validate_certificate_association(cls, certificate):
        """Raise TLSAError if certificate association is not a certificate or public key, or return None.

        Args:
            certificate (str): Certificate association data from TLSA record.

        Return:
            None

        Raise:
            TLSAError if parsing fails.
        """
        try:
            # First, we try to parse as x509
            der = cls.certificate_association_to_der(certificate)
            cls.build_x509_object(der)
            return
        except (ValueError, binascii.Error) as err:
            pass
        try:
            # Next, we try as raw public key
            der = cls.certificate_association_to_der(certificate)
            cls.build_public_key_object_from_der(der)
            return
        except (ValueError, binascii.Error) as err:
            pass
        raise TLSAError("The certificate association does not parse as a certificate or raw public key.")

    @classmethod
    def validate_certificate_chain(cls, entity_certificate, ca_certificates):
        """Return True if PKI trust chain is established from entity to CA.
        
        This method attempts cryptographic validation of ``entity_certificate`` 
        against the list of ``ca_certificates``. This method only checks 
        public keys and signatures, independent of any x509v3 extensions.

        The validation process completes successfully if a self-signed CA
        certificate is encountered in ``ca_certificates``, which terminates a
        cryptographically-validated chain from the entity certificate.

        Args:
            entity_certificate (str): Entity certificate to be verified.
            ca_certificates (list of str): List of CA certificates for validating
                ``entity_certificate``.
        
        returns:
            (True, None) if certificate validates.
            (False, str) if certificate does not validate, and str will contain the reason.
        """
        validation = {cls.get_subject_key_id_from_certificate(c): c
                      for c in ca_certificates}
        ca_skis = [x for x in validation.keys()]
        for v in ca_skis:
            if not PKI.is_a_ca_certificate(validation[v]):
                print("Rejecting non-ca certificate with SKI {}".format(v))
                del(validation[v])
        # Set the initial cert for chain validation to the entity certificate
        currently_validating = x509.load_pem_x509_certificate(entity_certificate, default_backend()).public_bytes(serialization.Encoding.PEM)
        if not validation:
            return (False, "No CA certificates supplied!")
        # While we still have certs in the list...
        while validation:
            current_aki = cls.get_authority_key_id_from_certificate(currently_validating)
            # If we don't have a CA cert that matches the current entity's AKI, we bail.
            if current_aki not in validation:
                msg = "Parent certificate not found!"
                return (False, msg)
            identified_parent = validation[current_aki]
            # If the signature doesn't match, bail.
            if not cls.verify_certificate_signature(currently_validating, identified_parent):
                msg = "Cryptographic certificate validation failed!"
                return (False, msg)
            # If the parent CA certificate is self-signed...
            if cls.get_authority_key_id_from_certificate(identified_parent) == cls.get_subject_key_id_from_certificate(identified_parent):
                return (True, None)
            currently_validating = x509.load_pem_x509_certificate(validation[current_aki], default_backend()).public_bytes(serialization.Encoding.PEM)
            del(validation[current_aki])
        msg = "Unable to build trust chain to self-signed CA certificate."
        return (False, msg)

    @classmethod
    def verify_certificate_signature(cls, certificate, ca_certificate):
        """Return True if certificate was signed by ca_certificate.

        Args:
            entity_certificate (str): entity certificate in DER or PEM format.
            ca_certificate (str): CA certificate in DER or PEM format.

        Return: 
            bool: True if the ca_certificate validates the entity_certificate.
        """
        issuer_public_key = cls.build_x509_object(ca_certificate).public_key()
        cert_to_check = cls.build_x509_object(certificate)
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
    def verify_dnsname(cls, dns_name, certificate):
        """Return True if the first dNSName in the SAN matches."""
        x5_obj = cls.build_x509_object(certificate)
        san_dns_names = cls.get_dnsnames_from_cert(x5_obj)
        if san_dns_names[0] != dns_name:
            return False
        return True