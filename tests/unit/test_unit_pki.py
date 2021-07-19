"""Test the DANE object."""
import os

import pytest

from dane_discovery.pki import PKI
from dane_discovery.exceptions import TLSAError


here_dir = os.path.dirname(os.path.abspath(__file__))
dyn_assets_dir = os.path.join(here_dir, "../fixtures/dynamic/")
rsa_identity_name = "rsa.air-quality-sensor._device.example.net"
ecc_identity_name = "ecc.air-quality-sensor._device.example.net"
identity_names = [rsa_identity_name, ecc_identity_name]
ca_root_cert_name = "rootca.example.net.cert.pem"
ca_intermediate_cert_name = "intermediateca.example.net.cert.pem"


class TestUnitPKI:
    """Unit tests for DANE."""

    def get_dyn_asset(self, asset_name):
        """Return the contents of a file from the dynamic assets dir."""
        asset_path = os.path.join(dyn_assets_dir, asset_name)
        with open(asset_path, "rb") as asset:
            return asset.read()

    def test_unit_pki_validate_bad_certificate_association(self):
        """Ensure that failed validation raises TLSAError."""
        with pytest.raises(TLSAError):
            PKI.validate_certificate_association("3082045130820339A00302010270E".encode())
        with pytest.raises(TLSAError):
            PKI.validate_certificate_association("abc123")

    def test_unit_pki_build_bad_x509(self):
        """Ensure that bad cert raises ValueError."""
        with pytest.raises(ValueError):
            PKI.build_x509_object("abc123")
            assert False

    def test_unit_pki_format_keyid(self):
        """Make sure that the KeyID formatter is correct."""
        desired = "ab-cd-ef-gh"
        instring = "abcdefgh"
        assert PKI.format_keyid(instring) == desired

    def test_unit_pki_is_a_ca_certificate(self):
        """Make sure we correctly identify CA certificates."""
        for c in [ca_root_cert_name, ca_intermediate_cert_name]:
            certificate = self.get_dyn_asset(c)
            assert PKI.is_a_ca_certificate(certificate)
    
    def test_unit_pki_is_a_ca_certificate_false(self):
        """Make sure we don't incorrectly identify CA certificates."""
        for c in [rsa_identity_name, ecc_identity_name]:
            certificate = self.get_dyn_asset("{}.cert.pem".format(c))
            assert not PKI.is_a_ca_certificate(certificate)

    def test_unit_pki_serialize_certificate(self):
        """Serialize then deserialize a certificate/pubkey."""
        for c in identity_names:
            certificate = self.get_dyn_asset("{}.cert.pem".format(c))
            x5_obj = PKI.build_x509_object(certificate)
            der = PKI.serialize_cert(x5_obj, "DER")
            pem = PKI.serialize_cert(x5_obj, "PEM")
            rpk_der = PKI.serialize_cert(x5_obj, "RPK_DER")
            assert PKI.build_x509_object(der)
            assert PKI.build_x509_object(pem)
            assert PKI.build_public_key_object_from_der(rpk_der)
    
    def test_unit_pki_serialize_certificate_unsupported_format(self):
        """Attempt to serialize an unsupported certificate format."""
        certificate = self.get_dyn_asset("{}.cert.pem".format(rsa_identity_name))
        with pytest.raises(ValueError):
            PKI.serialize_cert(certificate, "UNSUPPORTED_FORMAT")

    def test_unit_pki_validate_certificate_chain_success(self):
        """Validate a certificate chain."""
        ca_certs = [self.get_dyn_asset(c) for 
                    c in [ca_root_cert_name, ca_intermediate_cert_name]]
        entity_cert = self.get_dyn_asset("{}.cert.pem".format(rsa_identity_name))
        success, _reason = PKI.validate_certificate_chain(entity_cert, ca_certs)
        assert success

    def test_unit_pki_validate_certificate_chain_fail_rootless(self):
        """Fail to validate a rootless a certificate chain."""
        ca_certs = [self.get_dyn_asset(c) for 
                    c in [ca_intermediate_cert_name]]
        entity_cert = self.get_dyn_asset("{}.cert.pem".format(rsa_identity_name))
        success, _reason = PKI.validate_certificate_chain(entity_cert, ca_certs)
        assert success is False

    def test_unit_pki_validate_certificate_chain_fail_no_intermediate(self):
        """Fail to validate a broken a certificate chain."""
        ca_certs = [self.get_dyn_asset(c) for 
                    c in [ca_root_cert_name]]
        entity_cert = self.get_dyn_asset("{}.cert.pem".format(rsa_identity_name))
        success, _reason = PKI.validate_certificate_chain(entity_cert, ca_certs)
        assert success is False

    def test_unit_pki_validate_certificate_signature(self):
        """Use a certificate to validate a certificate."""
        ca_cert = self.get_dyn_asset(ca_intermediate_cert_name)
        entity_certs = [self.get_dyn_asset("{}.cert.pem".format(x)) for x in identity_names]
        for x in entity_certs:
            assert PKI.verify_certificate_signature(x, ca_cert)

    def test_unit_pki_validate_certificate_signature_fail(self):
        """Use a certificate to unsuccessfully validate a certificate."""
        ca_cert = self.get_dyn_asset("{}.cert.pem".format(rsa_identity_name))
        entity_certs = [self.get_dyn_asset("{}.cert.pem".format(x)) for x in identity_names]
        for x in entity_certs:
            assert PKI.verify_certificate_signature(x, ca_cert) is False

    def test_unit_pki_validate_dnsname(self):
        """Validate that the first DNS name in the certificate matches."""
        dns_name = rsa_identity_name
        certificate = self.get_dyn_asset("{}.cert.pem".format(dns_name))
        assert PKI.verify_dnsname(dns_name, certificate)
    
    def test_unit_pki_validate_dnsname_fail(self):
        """Validate that the first DNS name in the certificate matches."""
        dns_name = "whatever.example"
        certificate = self.get_dyn_asset("{}.cert.pem".format(rsa_identity_name))
        assert PKI.verify_dnsname(dns_name, certificate) is False
    
        