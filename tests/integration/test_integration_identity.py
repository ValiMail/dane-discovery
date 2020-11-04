"""Test the DANE object."""
import os

import pytest
import requests_mock

from dane_discovery.dane import DANE
from dane_discovery.identity import Identity
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


here_dir = os.path.dirname(os.path.abspath(__file__))
dyn_assets_dir = os.path.join(here_dir, "../fixtures/dynamic/")
identity_name = "abc123.air-quality-sensor._device.example.net"
ca_certificate_name = "ca.example.net.cert.pem"


class TestIntegrationIdentity:
    """Integration tests for DANE."""

    def get_dyn_asset(self, asset_name):
        """Return the contents of a file from the dynamic assets dir."""
        asset_path = os.path.join(dyn_assets_dir, asset_name)
        with open(asset_path, "rb") as asset:
            return asset.read()

    def tlsa_for_cert(self, id_name):
        """Return a TLSA record for identity name."""
        file_name = "{}.cert.pem".format(id_name)
        file_contents = self.get_dyn_asset(file_name)
        tlsa = DANE.generate_tlsa_record(3, 0, 0, file_contents)
        return "name.example.com 123 IN TLSA {}".format(tlsa)

    def test_integration_identity_print_x509(self):
        """Test printing identity certificate metadata."""
        identity = Identity(identity_name)
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name))
        identity.public_credentials = [identity.process_tlsa(record) for record
                                       in [tlsa_dict]]
        report = identity.__repr__()
        print(report)
        assert isinstance(report, str)
        assert "extension" in report

    def test_integration_identity_load_private_key(self):
        """Test loading a private key from PEM data."""
        key_pem = self.get_dyn_asset("{}.key.pem".format(identity_name))
        key_obj = Identity.load_private_key(key_pem)
        assert isinstance(key_obj, RSAPrivateKey)

    def test_integration_identity_verify_certificate_signature_success(self):
        """Test CA signature validation success."""
        entity_certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
        ca_certificate = self.get_dyn_asset(ca_certificate_name)
        assert Identity.verify_certificate_signature(entity_certificate, ca_certificate)

    def test_integration_identity_verify_certificate_signature_fail(self):
        """Test CA signature validation failure."""
        entity_certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
        ca_certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
        assert not Identity.verify_certificate_signature(entity_certificate, ca_certificate)
    
    def test_integration_identity_generate_url_for_ca_certificate(self):
        """Test generation of the CA certificate URL."""
        id_name = "123.testing.name._device.example.com"
        auth_name = "https://authority._device.example.com/ca.pem"
        result = Identity.generate_url_for_ca_certificate(id_name)
        assert  result == auth_name

    def test_integration_identity_generate_url_for_ca_certificate_malformed(self):
        """Test failure of the CA certificate URL generator."""
        id_name = "123.testing.name.devices.example.com"
        with pytest.raises(ValueError):
            Identity.generate_url_for_ca_certificate(id_name)
            assert False

    def test_integration_get_ca_certificate_for_identity_fail_valid(self):
        """Test failure to get a CA certificate for a valid identity name."""
        id_name = "123.testing._device.example.com"
        with pytest.raises(ValueError):
            Identity.get_ca_certificate_for_identity(id_name)
            assert False

    def test_integration_get_ca_certificate_for_identity_fail_invalid(self):
        """Test failure to get a CA certificate for an invalid identity name."""
        id_name = "123.testing.device.example.com"
        with pytest.raises(ValueError):
            Identity.get_ca_certificate_for_identity(id_name)
            assert False

    def test_integration_get_ca_certificate_for_identity_success(self, requests_mock):
        """Test getting a CA certificate for an identity name."""
        id_name = "123.testing._device.example.com"
        ca_certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
        requests_mock.get("https://authority._device.example.com/ca.pem", 
                          content=ca_certificate)
        retrieved = Identity.get_ca_certificate_for_identity(id_name)
        assert retrieved == ca_certificate
        