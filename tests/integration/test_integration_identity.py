"""Test the DANE object."""
import os

import pytest
import requests_mock

from dane_discovery.dane import DANE
from dane_discovery.identity import Identity
from dane_discovery.exceptions import TLSAError
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
        report = identity.report()
        print(report)
        assert isinstance(report, str)
        assert "extension" in report

    def test_integration_identity_load_private_key(self):
        """Test loading a private key from PEM data."""
        key_pem = self.get_dyn_asset("{}.key.pem".format(identity_name))
        key_obj = Identity.load_private_key(key_pem)
        assert isinstance(key_obj, RSAPrivateKey)

    def test_integration_identity_get_entity_certificate_by_type_fail(self, requests_mock):
        """Test getting entity certificate by type, and failing validation."""
        identity = Identity(identity_name)
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name))
        identity.public_credentials = [identity.process_tlsa(record) for record
                                       in [tlsa_dict]]
        identity.dnssec = False
        identity.tls = True
        identity.tcp = True
        ca_certificate = self.get_dyn_asset(ca_certificate_name)
        requests_mock.get("https://authority.device.example.net/ca.pem", 
                          content=ca_certificate)
        with pytest.raises(TLSAError):
            identity.get_first_entity_certificate_by_type("DANE-EE", strict=True)
            print(identity.report())

    def test_integration_identity_get_entity_certificate_by_type(self):
        """Test getting entity certificate by type, present and absent, strict."""
        identity = Identity(identity_name)
        print("Identity: {}".format(identity_name))
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name))
        print("TLSA: {}".format(tlsa_dict))
        identity.public_credentials = [identity.process_tlsa(record) for record
                                       in [tlsa_dict]]
        identity.dnssec = True
        identity.tls = True
        identity.tcp = True
        # We get a cert here.
        cert = identity.get_first_entity_certificate_by_type("DANE-EE", strict=True)
        print(cert)
        assert cert != ""
        # And here we don't have a match.
        cert = identity.get_first_entity_certificate_by_type("PKIX-EE", strict=True)
        assert cert == ""

    