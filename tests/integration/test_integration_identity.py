"""Test the DANE object."""
import os
import pprint
from cryptography.hazmat.primitives import serialization

import pytest
# import requests_mock
from unittest.mock import MagicMock

from dane_discovery.dane import DANE
from dane_discovery.identity import Identity
from dane_discovery.exceptions import TLSAError
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


here_dir = os.path.dirname(os.path.abspath(__file__))
dyn_assets_dir = os.path.join(here_dir, "../fixtures/dynamic/")
rsa_identity_name = "rsa.air-quality-sensor._device.example.net"
ecc_identity_name = "ecc.air-quality-sensor._device.example.net"
identity_names = [rsa_identity_name, ecc_identity_name]
ca_root_cert_name = "rootca.example.net.cert.pem"
ca_intermediate_cert_name = "intermediateca.example.net.cert.pem"


class TestIntegrationIdentity:
    """Integration tests for DANE."""

    def get_dyn_asset(self, asset_name):
        """Return the contents of a file from the dynamic assets dir."""
        asset_path = self.get_path_for_dyn_asset(asset_name)
        with open(asset_path, "rb") as asset:
            return asset.read()

    def get_path_for_dyn_asset(self, asset_name):
        """Return the path for a dynamically-generated asset."""
        return os.path.join(dyn_assets_dir, asset_name)

    def tlsa_for_cert(self, id_name, cert_usage=3, selector=0, matching_type=0):
        """Return a TLSA record for identity name."""
        file_name = "{}.cert.pem".format(id_name)
        file_contents = self.get_dyn_asset(file_name)
        tlsa = DANE.generate_tlsa_record(cert_usage, selector, 
                                         matching_type, file_contents)
        return "name.example.com 123 IN TLSA {}".format(tlsa)

    def test_integration_identity_print_x509(self):
        """Test printing identity certificate metadata."""
        for identity_name in identity_names:
            identity = Identity(identity_name)
            tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name))
            identity.dane_credentials = [identity.process_tlsa(record) for record
                                         in [tlsa_dict]]
            identity.dnssec = True
            print(dir(identity))
            pprint.pprint(identity.dane_credentials)
            report = identity.report()
            print(report)
            assert isinstance(report, str)
            assert "extension" in report

    def test_integration_identity_load_private_key(self):
        """Test loading a private key from PEM data."""
        for identity_name in identity_names:
            key_pem = self.get_dyn_asset("{}.key.pem".format(identity_name))
            key_obj = Identity.load_private_key(key_pem)
            assert isinstance(key_obj, RSAPrivateKey) or isinstance(key_obj, EllipticCurvePrivateKey)

    def test_integration_identity_get_entity_certificate_by_type_fail(self, requests_mock):
        """Test getting entity certificate by type, and failing validation."""
        for identity_name in identity_names:
            identity = Identity(identity_name)
            tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name))
            identity.dane_credentials = [identity.process_tlsa(record) for record
                                         in [tlsa_dict]]
            identity.dnssec = False
            identity.tls = True
            identity.tcp = True
            with pytest.raises(TLSAError):
                identity.get_first_entity_certificate_by_type("DANE-EE", strict=True)
                print(identity.report())

    def test_integration_identity_get_entity_certificate_by_type(self):
        """Test getting entity certificate by type, present and absent, strict."""
        for identity_name in identity_names:
            identity = Identity(identity_name)
            print("Identity: {}".format(identity_name))
            tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name))
            print("TLSA: {}".format(tlsa_dict))
            identity.dane_credentials = [identity.process_tlsa(record) for record
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

    def test_integration_identity_get_first_entity_certificate(self):
        """Test getting entity certificate, strict."""
        for identity_name in identity_names:
            identity = Identity(identity_name)
            print("Identity: {}".format(identity_name))
            tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name))
            print("TLSA: {}".format(tlsa_dict))
            identity.dane_credentials = [identity.process_tlsa(record) for record
                                         in [tlsa_dict]]
            identity.dnssec = True
            identity.tls = True
            identity.tcp = True
            # We get a cert here.
            cert = identity.get_first_entity_certificate(strict=True)

    def test_integration_identity_validate_certificate_pkix_cd_pass(self, requests_mock):
        """Test validating a local certificate when certificate_usage is 4."""
        identity_name = ecc_identity_name
        certificate_path = self.get_path_for_dyn_asset("{}.cert.pem".format(identity_name))
        certificate = self.get_dyn_asset(certificate_path)
        identity = Identity(identity_name)
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name, 4, 0, 0))
        identity.dane_credentials = [identity.process_tlsa(record) for record
                                     in [tlsa_dict]]
        identity.tls = True
        identity.tcp = True
        intermediate_certificate = self.get_dyn_asset(ca_intermediate_cert_name)
        root_certificate = self.get_dyn_asset(ca_root_cert_name)
        intermediate_ski = DANE.get_authority_key_id_from_certificate(certificate)
        root_ski = DANE.get_authority_key_id_from_certificate(intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(intermediate_ski), 
                              content=intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(root_ski), 
                              content=root_certificate)
        assert identity.validate_certificate(certificate)
    
    def test_integration_identity_validate_certificate_pkix_cd_dnssec_pass(self, requests_mock):
        """Test validating a local certificate when certificate_usage is 4 and DNSSEC is present."""
        identity_name = ecc_identity_name
        certificate_path = self.get_path_for_dyn_asset("{}.cert.pem".format(identity_name))
        certificate = self.get_dyn_asset(certificate_path)
        identity = Identity(identity_name)
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name, 4, 0, 0))
        identity.dane_credentials = [identity.process_tlsa(record) for record
                                     in [tlsa_dict]]
        identity.tls = True
        identity.tcp = True
        identity.dnssec = True
        intermediate_certificate = self.get_dyn_asset(ca_intermediate_cert_name)
        root_certificate = self.get_dyn_asset(ca_root_cert_name)
        intermediate_ski = DANE.get_authority_key_id_from_certificate(certificate)
        root_ski = DANE.get_authority_key_id_from_certificate(intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(intermediate_ski), 
                              content=intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(root_ski), 
                              content=root_certificate)
        assert identity.validate_certificate(certificate)

    def test_integration_identity_get_pkix_cd_trust_chain(self, requests_mock):
        """Test retrieval of a PKIX-CD trust chain."""
        identity_name = ecc_identity_name
        certificate_path = self.get_path_for_dyn_asset("{}.cert.pem".format(identity_name))
        certificate = self.get_dyn_asset(certificate_path)
        identity = Identity(identity_name)
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name, 4, 0, 0))
        identity.dane_credentials = [identity.process_tlsa(record) for record
                                     in [tlsa_dict]]
        identity.tls = True
        identity.tcp = True
        identity.dnssec = True
        intermediate_certificate = self.get_dyn_asset(ca_intermediate_cert_name)
        root_certificate = self.get_dyn_asset(ca_root_cert_name)
        intermediate_ski = DANE.get_authority_key_id_from_certificate(certificate)
        root_ski = DANE.get_authority_key_id_from_certificate(intermediate_certificate)
        mock_dane = DANE
        mock_dane.get_a_record = MagicMock(return_value="192.168.1.1")
        requests_mock.get("https://192.168.1.1/.well-known/ca/{}.pem".format(intermediate_ski), 
                              content=intermediate_certificate)
        requests_mock.get("https://192.168.1.1/.well-known/ca/{}.pem".format(root_ski), 
                              content=root_certificate)
        chain = identity.get_pkix_cd_trust_chain(certificate)
        assert chain[0] == DANE.build_x509_object(certificate).public_bytes(serialization.Encoding.PEM)
        assert chain[1] == DANE.build_x509_object(intermediate_certificate).public_bytes(serialization.Encoding.PEM)
        assert chain["root"] == DANE.build_x509_object(root_certificate).public_bytes(serialization.Encoding.PEM)

    def test_integration_identity_validate_certificate_pkix_cd_fail(self, requests_mock):
        """Test validating a local certificate when certificate_usage is 4.
        CA certificate found is the EE certificate, which should fail.
        """
        identity_name = ecc_identity_name
        certificate_path = self.get_path_for_dyn_asset("{}.cert.pem".format(identity_name))
        certificate = self.get_dyn_asset(certificate_path)
        identity = Identity(identity_name)
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name, 4, 0, 0))
        identity.dane_credentials = [identity.process_tlsa(record) for record
                                     in [tlsa_dict]]
        identity.tls = True
        identity.tcp = True
        intermediate_certificate = self.get_dyn_asset(ca_intermediate_cert_name)
        root_certificate = self.get_dyn_asset(ca_root_cert_name)
        intermediate_ski = DANE.get_authority_key_id_from_certificate(certificate)
        root_ski = DANE.get_authority_key_id_from_certificate(intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(intermediate_ski), 
                              content=intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(root_ski), 
                              content=certificate)
        valid, _reason = identity.validate_certificate(certificate)
        assert not valid
    
    def test_integration_identity_validate_certificate_pkix_cd_dnssec_fail(self, requests_mock):
        """Test validating a local certificate when certificate_usage is 4 and DNSSEC is present.
        CA certificate found is the EE certificate, which should fail.
        """
        identity_name = ecc_identity_name
        certificate_path = self.get_path_for_dyn_asset("{}.cert.pem".format(identity_name))
        certificate = self.get_dyn_asset(certificate_path)
        identity = Identity(identity_name)
        tlsa_dict = DANE.process_response(self.tlsa_for_cert(identity_name, 4, 0, 0))
        identity.dane_credentials = [identity.process_tlsa(record) for record
                                     in [tlsa_dict]]
        identity.tls = True
        identity.tcp = True
        identity.dnssec = True
        aki = DANE.get_authority_key_id_from_certificate(certificate)
        ca_certificate = self.get_dyn_asset(certificate_path)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(aki), 
                          content=ca_certificate)
        valid, _reason = identity.validate_certificate(certificate)
        assert not valid

    def test_integration_identity_get_all_certs_for_identity(self, requests_mock):
        """Test retrieval of all PKIX-CD certs for an identity."""
        identity_name1 = ecc_identity_name
        identity_name2 = rsa_identity_name
        identity = Identity(identity_name1)
        tlsa_dict1 = DANE.process_response(self.tlsa_for_cert(identity_name1, 4, 0, 0))
        tlsa_dict2 = DANE.process_response(self.tlsa_for_cert(identity_name2, 4, 0, 0))
        tlsa_dict3 = DANE.process_response(self.tlsa_for_cert(identity_name1, 3, 0, 0))
        tlsa_dict4 = DANE.process_response(self.tlsa_for_cert(identity_name1, 1, 0, 0))
        identity.dane_credentials = [identity.process_tlsa(record) for record
                                     in [tlsa_dict1, tlsa_dict2, tlsa_dict3, tlsa_dict4]]
        identity.tls = True
        identity.tcp = True
        identity.dnssec = True
        certificate_path = self.get_path_for_dyn_asset("{}.cert.pem".format(identity_name1))
        certificate = self.get_dyn_asset(certificate_path)
        # Both identities have the same CA.
        intermediate_certificate = self.get_dyn_asset(ca_intermediate_cert_name)
        root_certificate = self.get_dyn_asset(ca_root_cert_name)
        intermediate_ski = DANE.get_authority_key_id_from_certificate(certificate)
        root_ski = DANE.get_authority_key_id_from_certificate(intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(intermediate_ski), 
                              content=intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(root_ski), 
                              content=root_certificate)
        certs = identity.get_all_certificates()
        # We only have one valid cert, across four TLSA records.
        pprint.pprint(certs)
        assert len(certs) == 1

    def test_integration_identity_get_all_certs_for_identity_filtered(self, requests_mock):
        """Test retrieval of all PKIX-CD certs for an identity."""
        identity_name1 = ecc_identity_name
        identity_name2 = rsa_identity_name
        identity = Identity(identity_name1)
        tlsa_dict1 = DANE.process_response(self.tlsa_for_cert(identity_name1, 4, 0, 0))
        tlsa_dict2 = DANE.process_response(self.tlsa_for_cert(identity_name2, 4, 0, 0))
        tlsa_dict3 = DANE.process_response(self.tlsa_for_cert(identity_name1, 3, 0, 0))
        tlsa_dict4 = DANE.process_response(self.tlsa_for_cert(identity_name1, 1, 0, 0))
        identity.dane_credentials = [identity.process_tlsa(record) for record
                                     in [tlsa_dict1, tlsa_dict2, tlsa_dict3, tlsa_dict4]]
        identity.tls = True
        identity.tcp = True
        identity.dnssec = True
        certificate_path = self.get_path_for_dyn_asset("{}.cert.pem".format(identity_name1))
        certificate = self.get_dyn_asset(certificate_path)
        # Both identities have the same CA.
        intermediate_certificate = self.get_dyn_asset(ca_intermediate_cert_name)
        root_certificate = self.get_dyn_asset(ca_root_cert_name)
        intermediate_ski = DANE.get_authority_key_id_from_certificate(certificate)
        root_ski = DANE.get_authority_key_id_from_certificate(intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(intermediate_ski), 
                              content=intermediate_certificate)
        requests_mock.get("https://device.example.net/.well-known/ca/{}.pem".format(root_ski), 
                              content=root_certificate)
        certs = identity.get_all_certificates(filters=["PKIX-EE"])
        # We only have one PKIX-EE cert.
        assert len(certs) == 1

