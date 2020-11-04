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


class Identity:
    """Represent a DANE identity."""

    descr = {"certificate_usage":
             {0: "CA Constraint.",
              1: "PKIX-EE",
              2: "DANE-TA",
              3: "DANE-EE"},
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
        self.set_public_credentials(dnsname, resolver_override)

    def __repr__(self):
        """Format a report for the identity.

        Prints the query context (DNSSEC, etc) as well as information about
        the TLSA records stored at the identity's name.
        """
        fmt = "Name: {}\n".format(self.dnsname)
        fmt += ("Request context:\n DNSSEC: {}\n TLS: {}\n "
                "TCP: {}\n".format(self.dnssec, self.tls, self.tcp))
        cred_index = 0
        for cert in self.public_credentials:
            fmt += ("Credential index: {}\n"
                    " certificate usage: {}\n"
                    " selector: {}\n"
                    " matching type: {}\n".format(cred_index,
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
            print(dir(x509_ext.value))
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

        Dictionary keys:
            ``tlsa_fields``: A list of raw fields from the TLSA record.
            ``certificate_usage``: Text description of the TLSA field.
            ``matching_type``: Text description of the TLSA field.
            ``selector``: Text description of the TLSA field.
            ``certificate_metadata``: Metadata parsed from the certificate.
            ``public_key_object``: If the TLSA record contains a public key,
                this will be the same object as generated by
                cryptography.hazmat.primitives.serialization.load_der_public_key()
        """
        cert_association = tlsa_record["certificate_association"]
        cert_der = DANE.certificate_association_to_der(cert_association)
        retval = {"certificate_metadata": None, "public_key_object": None}
        retval["tlsa_fields"] = [tlsa_record[x] for x in
                                 ["certificate_usage", "selector",
                                  "matching_type", "certificate_association"]]
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
        try:
            issuer_public_key.verify(cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes, padding.PKCS1v15(),
                cert_to_check.signature_hash_algorithm)
        except InvalidSignature:
            return False
        return True

    @classmethod
    def generate_url_for_ca_certificate(cls, dns_name):
        """Return a URL for the identity's ca certificate.

        An identity conforming to DANE PKIX-CD must have
        the signing CA certificate available at a known 
        location in DNS, relative to the identity itself.

        This assumes the first underscore label found while
        parsing from TLD toward hostname ( ``._device.``
        for devices, or ``._service.``, or ``._whatever.``) 
        to be the anchor label for constructing the URL 
        where we expect to find the CA certificate that 
        can be used to verify any PKIX-CD DANE records 
        associated with ``dns_name``.

        Args:
            dns_name (str): DNS name of the identity.
        
        Raise:
            ValueError if no underscore label in ``dns_name``.
            
        Return: 
            str: URL where a CA certificate should be found.
        """
        # DNS name to labels
        authority_dns_labels = []
        identity_labels = dns_name.split(".")
        identity_labels.reverse()
        # Build DNS name from right to left, stopping at underscore label.
        for label in identity_labels:
            if label.startswith("_"):
                authority_dns_labels.append(label)
                authority_dns_labels.append("authority")
                break
            else:
                authority_dns_labels.append(label)
        if not authority_dns_labels[-1] == "authority":
            raise ValueError("Malformed identity name {}.".format(dns_name))
        authority_dns_labels.reverse()
        authority_hostname = ".".join(authority_dns_labels)
        authority_url = urllib.parse.urlunsplit(["https", authority_hostname, "ca.pem", "", ""])
        return authority_url

    @classmethod
    def get_ca_certificate_for_identity(cls, identity_name):
        """Return the CA certificate for verifying identity_name.
        
        Returns the PEM representation of the CA certificate
        used for verifying any DANE PKIX-CD certificate 
        associated with ``identity_name``.

        Args:
            identity_name (str): DNS name of identity.

        Raise:
            ValueError if no CA certificate is found or the
                certificate is not parseable.

        Return:
            str: PEM of CA signing certificate.
        """
        authority_url = cls.generate_url_for_ca_certificate(identity_name)
        try:
            r = requests.get(authority_url)
            presumed_pem = r.content
            # The following line raises ValueError if it fails to parse.
            x509.load_pem_x509_certificate(presumed_pem, default_backend()) 
            return presumed_pem
        except requests.exceptions.RequestException as err:
            msg = "Error making request: {}".format(err)
            raise ValueError(msg)

