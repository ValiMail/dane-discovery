"""Test the DANE object."""
import binascii
import os
import pprint

from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import serialization
import dns
import pytest
from unittest.mock import MagicMock

from dane_discovery.dane import DANE
from dane_discovery.exceptions import TLSAError


here_dir = os.path.dirname(os.path.abspath(__file__))
dyn_assets_dir = os.path.join(here_dir, "../fixtures/dynamic/")
rsa_identity_name = "rsa.air-quality-sensor._device.example.net"
ecc_identity_name = "ecc.air-quality-sensor._device.example.net"
identity_names = [rsa_identity_name, ecc_identity_name]
ca_certificate_name = "ca.example.net.cert.pem"
tlsa_record_full = (
    "red._device.example.com. 373 IN TLSA 3 0 0 308203863082026ea00"
    "302010202147072506e7e305c5567afb31a27426b1af4b16c5c300d06092a864"
    "886f70d01010b05003068310b30090603550406130255 53310b300906035504"
    "080c0243413116301406035504070c0d53616e204672616e636973636f311030"
    "0e060355040a0c076578616d706c653122302006035504 030c197265642d776"
    "f6f642e5f6465766963652e73697463682e696f301e170d32303130303832323"
    "13634335a170d3230313031383232313634335a3068310b 3009060355040613"
    "025553310b300906035504080c0243413116301406035504070c0d53616e2046"
    "72616e636973636f3110300e060355040a0c076578616d70 6c6531223020060"
    "35504030c197265642d776f6f642e5f6465766963652e73697463682e696f308"
    "20122300d06092a864886f70d01010105000382010f003082 010a0282010100"
    "a149bfe49428cb8dab03aba643bffd9d4fb9dc25b55fe61c27670519494730c6"
    "e97e42688c2e46da41532285ece3c86c01ef4a4f890b472d19 77991748cd2b2"
    "d0ce0396e161baa713fad2ae52682025bb56c5c4aef9b7ae9a8b8e32c6a1700d"
    "a303f4b34fc3034b6fcad405a1523ead4a39dcf6b10c225fc26 88387bcd505e"
    "0881e5a92c5f58d75783ae186fa05352f0169e0f7155832c115a43824a00cfcf"
    "d8f66c0281e16bbb676f4355063d9c818934408089e0e7c4e897 aa77a955d66"
    "6a0f22b83cae9478eaa927a4a85271c5179e728de664ebdb65b4b45d700be0a0"
    "7e05ca29fc44fe8080d270fd03de132d391ad7fd366d22bea3c24 7cfbf2f806"
    "acbf0203010001a328302630240603551d11041d301b82197265642d776f6f64"
    "2e5f6465766963652e73697463682e696f300d06092a864886f70d 01010b050"
    "00382010100405fc8b5e532083b3c268e9ba91af6d87334a8de5fb2acddcc0ed"
    "18d4dd20848884ae847ff290afe37e30f19b0295d5f0c27dbe181a5 9aea6c08"
    "827ed9002da755cc03cfde006ee7e2cd9e28a15667a4a7e3c1c2e5285a761f94"
    "e9c299cbb1150dd8aa6a7f654c52fcae5cdd250f74ccad2969fb7fad b1ecbcb"
    "702fed10738afb7e685d91a77014534ef1869425a6afc3f626cfed237b491c08"
    "6439dc547cedd0ea02613c374e51d702b5932ed62450ce6b9612368a7 8ed222"
    "127d3cf0532f8e4c5216c88afea9428a0554c98d4920230934a805b967b00bc7"
    "bf8a3d95a4890e260b47da3aa8f6697d2afec2addea5287467c7172263 cb97f"
    "e584220315e21f6"
    )

tlsa_record_shorts = [
    "red._device.example.com. 373 IN TLSA 3 1 1 55F6DB74C524ACCA28B52C0BCFC28EEC4596F90D00C2056010AE7990 1B2EB049",
    "red._device.example.com. 373 IN TLSA 3 1 1 736A6032543CF64DE9D4CFBD5BDFFD329027FE1FE860B2396954A9D9 DB630FD1",
    "red._device.example.com. 373 IN TLSA 3 1 1 9D0062CA1CED50C2EB6785B9985B1B59ED3A14E9F27114BCC162F8AC FFEF8683"]


cert_sha256 = "67acae94572006c84d30c7eb2f043cf14fea7a5f6edf7e95b32e1f20ce6c49af"
cert_sha512 = "a49585190f8bd020e813f35cb277f1bf11cdcde7253b9c8626dadd006bd1d1748ca87d275444836d71b7fa3fea8bdf43a0a35fe541aa31c606ffcc2dcc350df1"
spki_sha256 = "9b2f169d699c8673f817cb3494fa1d9c89c4a46d2181b9461d73acf24fe63201"
spki_sha512 = "0973a8d47cadefe9143050375b4620f5bdbc9bb350b6adf05424e564b165d45280092221bae2c94e734eda2afad0d18daddbadbbaa51d89b33c22e39ca40bcd9"
sha_cert = """-----BEGIN CERTIFICATE-----
MIIERzCCAi8CFBoapaaqjiyhO4KDRLlmyDrKNIyrMA0GCSqGSIb3DQEBCwUAMFMx
CzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEZMBcGA1UECgwQRXhhbXBsZSBOZXR3
b3JrczEcMBoGA1UEAwwTRXhhbXBsZSBOZXR3b3JrcyBDQTAeFw0yMDA4MTIyMDUy
MjBaFw0yMTA4MjIyMDUyMjBaMG0xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEZ
MBcGA1UECgwQRXhhbXBsZSBOZXR3b3JrczE2MDQGA1UEAwwtYWJjMTIzLmFpci1x
dWFsaXR5LXNlbnNvci5fZGV2aWNlLmV4YW1wbGUubmV0MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAr0uHeWsH5tnnIctqMLuwEUP9O3kr7eb8LLozxJus
KX/bHz8pb2REBd+kAxAGkbneOZHsGKGgkOMyeAIV3+ptW/J/AOTL6I6Jq8jISLiX
fxo3T6o8pJZBavlJh648TckkhWwp3tZo4sDlXaU5TiyWsKdEDX8b3F6vk566WwE3
f6G3ni6tXOV7AwJaPj1MDJwkHwP7HeWWKpaWYKs/6Ll7OGx7bA5E5dKFtZrhn7CL
lqqkuK/4S57wCpqzF2i/D4wqOWoTlONCssc/b0ZiP/gpIDd0i5MvDpgICdKIFM2U
DcThDApIm0GFw/iTqbsPClI63Aju/Wp+7BMHhKAkwOtZuQIDAQABMA0GCSqGSIb3
DQEBCwUAA4ICAQA6CKyWV1to4iWMCc522/hnF6L3BGNQ/L79rEMimZXvVT5EXuO+
GVClc+s3GF9WlVEXx0ubAC3WLDhd9Hsgjd48+2Ax9aQfYVFuqOQSS8YrEQm+bIQG
1Br38BuI0I/bdDmULfU4ANIcXEszmKdrS/UQBHXQ4b/dY1fxCgMAP7HbLem32QC5
0tjlKIQbrhMP0i3eYhDdVR5SaIvMe3oax0CIIXkSvAeUyng2stLWj5CX7f1T+wGV
MQ3BCO/Gsw4WUxyAwvx6rWlyc2I8PSyN5l7VaRbQc4VrlszLEjIAWZwtzstq/HI1
RCFU2cl0aDV9w89NK256GUDf0ov9238LZLcF+LMZDueesOWPuvVdgJF/hReknZqx
8kxNUyfGp/hNAcB2DIiGVEBbhDL5SEdfBKbDVlgJUmoyzEkUeGvfYExinuQx9/Bw
OHl90ks1cNVCb3QIgNwxhf62n0xfDH9pFV3T+w3akek8yGSNt+c1xnetOLWqK/hT
AkaRR/0BsIYmLut4yMttAZ2TvESmesFFn5Sv6qLqkvGPa/8OY6TLtP0ke5hLKCWG
lXiVNLkJY58ZsWX6yaphAHiOD8iZR7wTYMO1bq0s3tvZUEBFhxIABGPZRXcLQXw4
l+a1hqYCoeQ8Wts5m9v1t6T443Qp1hT53Zel5zhRHa3Pxvnh2NsEZ6idGA==
-----END CERTIFICATE-----""".encode()




class TestIntegrationDane:
    """Integration tests for DANE."""

    def get_dyn_asset(self, asset_name):
        """Return the contents of a file from the dynamic assets dir."""
        asset_path = os.path.join(dyn_assets_dir, asset_name)
        with open(asset_path, "rb") as asset:
            return asset.read()

    def generate_rrset(self, dnsname, rrtype, msgs):
        """Return an rrset for testing."""
        rrset = [dns.rrset.from_text(dnsname, 86400, 'IN', rrtype, msg)
                 for msg in msgs]
        return rrset

    def generate_response(self, dnsname, rrtype, msgs):
        """Return an rrset for testing."""
        response = {"dnssec": False, "tcp": True, "tls": False,
                    "responses": msgs}
        return response

    def test_integration_dane_generate_sha_by_selector_0_1(self):
        """Test generating SHA256 against the full cert."""
        result = DANE.generate_sha_by_selector(sha_cert, "sha256", 0)
        assert result == cert_sha256

    def test_integration_dane_generate_sha_by_selector_0_2(self):
        """Test generating SHA512 against the full cert."""
        result = DANE.generate_sha_by_selector(sha_cert, "sha512", 0)
        assert result == cert_sha512

    def test_integration_dane_generate_sha_by_selector_1_1(self):
        """Test generating SHA256 against the public key."""
        result = DANE.generate_sha_by_selector(sha_cert, "sha256", 1)
        assert result == spki_sha256

    def test_integration_dane_generate_sha_by_selector_1_2(self):
        """Test generating SHA512 against the public key."""
        result = DANE.generate_sha_by_selector(sha_cert, "sha512", 1)
        assert result == spki_sha512

    def test_integration_dane_generate_sha_by_selector_bad_selector(self):
        """Test bad selector."""
        with pytest.raises(ValueError):
            DANE.generate_sha_by_selector(sha_cert, "sha512", 2)
            assert False

    def test_integration_dane_generate_sha_by_selector_bad_matching_type(self):
        """Test bad matching type."""
        with pytest.raises(ValueError):
            DANE.generate_sha_by_selector(sha_cert, "sha9999", 1)
            assert False

    def test_integration_dane_generate_tlsa_record_256(self):
        """Test generating SHA256."""
        assert DANE.generate_tlsa_record(0, 0, 1, sha_cert)

    def test_integration_dane_generate_tlsa_record_512(self):
        """Test generating SHA512."""
        assert DANE.generate_tlsa_record(0, 0, 2, sha_cert)

    def test_integration_dane_get_responses(self):
        """Test get_responses for DNSSEC."""
        test_dns_name = "pir.org"
        responses = DANE.get_responses(test_dns_name, "A", "1.1.1.1")
        assert "dnssec" in responses
        assert responses["dnssec"] is True

    def test_integration_dane_get_tlsa_records_noexist(self):
        """Test failure handling for nonexistent records."""
        test_dns_name = "_443._tcp.example.net"
        with pytest.raises(TLSAError):
            result = DANE.get_tlsa_records(test_dns_name)
            print(result)
            assert False

    def test_integration_dane_get_tlsa_records_noanswer(self):
        """Test failure handling for nonexistent records."""
        test_dns_name = "_443._tcp.example.net"
        with pytest.raises(TLSAError):
            DANE.get_tlsa_records(test_dns_name, "127.0.0.1")
            assert False

    def test_integration_dane_get_tlsa_records_sha(self):
        """Process short records."""
        test_dns_name = "_443._tcp.www.example.net"
        mock_dane = DANE
        response = self.generate_response(test_dns_name, "TLSA",
                                          tlsa_record_shorts)
        mock_dane.get_responses = MagicMock(return_value=response)
        result = DANE.get_tlsa_records(test_dns_name)
        assert isinstance(result, list)

    def test_integration_dane_get_tlsa_records_cert(self):
        """Get the TLSA records from other test site."""
        test_dns_name = "butterfly.example.net"
        mock_dane = DANE
        response = self.generate_response(test_dns_name, "TLSA",
                                          [tlsa_record_full])
        mock_dane.get_responses = MagicMock(return_value=response)
        result = DANE.get_tlsa_records(test_dns_name)
        assert isinstance(result, list)

    def test_integration_dane_get_tlsa_leaf_cert(self):
        """Get one TLSA record."""
        test_dns_name = "butterfly.example.net"
        mock_dane = DANE
        response = self.generate_response(test_dns_name, "TLSA",
                                          [tlsa_record_full])
        mock_dane.get_responses = MagicMock(return_value=response)
        result = DANE.get_first_leaf_certificate(test_dns_name)
        assert isinstance(result, dict)

    def test_integration_dane_get_tlsa_leaf_cert_convert_pem(self):
        """Get one TLSA record, convert to PEM."""
        test_dns_name = "butterfly.example.net"
        mock_dane = DANE
        response = self.generate_response(test_dns_name, "TLSA",
                                          [tlsa_record_full])
        mock_dane.get_responses = MagicMock(return_value=response)
        cert = DANE.get_first_leaf_certificate(test_dns_name)
        der_cert = DANE.certificate_association_to_der(cert["certificate_association"])  # NOQA
        pem = DANE.der_to_pem(der_cert)
        assert isinstance(pem, bytes)

    def test_integration_dane_get_tlsa_record_leaf_cert_none(self):
        """Get single TLSA record."""
        test_dns_name = "butterfly.example.net"
        mock_dane = DANE
        response = self.generate_response(test_dns_name, "TLSA",
                                          tlsa_record_shorts)
        mock_dane.get_responses = MagicMock(return_value=response)
        result = DANE.get_first_leaf_certificate(test_dns_name)
        assert result is None

    def test_integration_dane_generate_parse_tlsa_record(self):
        """Generate DANE record, attempt to parse."""
        for identity_name in identity_names:
            certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
            generated = DANE.generate_tlsa_record(3, 0, 0, certificate)
            full_record = "name.example.com 123 IN TLSA {}".format(generated)
            parsed = DANE.process_response(full_record)
            assert DANE.validate_certificate(parsed["certificate_association"]) is None  # NOQA
            test_der_cert = binascii.unhexlify(parsed["certificate_association"])
            control_der_cert = self.get_dyn_asset("{}.cert.der".format(identity_name))
            x5_obj = DANE.build_x509_object(test_der_cert)
            assert DANE.build_x509_object(control_der_cert)
            assert isinstance(x5_obj, Certificate)
            assert test_der_cert == control_der_cert

    def test_integration_dane_verify_certificate_signature_success(self):
        """Test CA signature validation success."""
        for identity_name in identity_names:
            print("Checking signature of {}'s certificate".format(identity_name))
            entity_certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
            ca_certificate = self.get_dyn_asset(ca_certificate_name)
            assert DANE.verify_certificate_signature(entity_certificate, ca_certificate)
            print("Success.")

    def test_integration_dane_verify_certificate_signature_fail(self):
        """Test CA signature validation failure."""
        for identity_name in identity_names:
            print("Checking signature of {}'s certificate".format(identity_name))
            entity_certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
            ca_certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
            assert not DANE.verify_certificate_signature(entity_certificate, ca_certificate)
            print("Failed, as expected.")
    
    def test_integration_dane_generate_url_for_ca_certificate(self):
        """Test generation of the CA certificate URL."""
        authority_hostname = "device.example.com"
        aki = "aa-bc-de-00-12-34"
        auth_name = "https://device.example.com/ca/aa-bc-de-00-12-34.pem"
        result = DANE.generate_url_for_ca_certificate(authority_hostname, aki)
        assert  result == auth_name

    def test_integration_dane_generate_authority_hostname_malformed(self):
        """Test failure of the authority hostname generator."""
        id_name = "123.testing.name.devices.example.com"
        with pytest.raises(ValueError):
            DANE.generate_authority_hostname(id_name)
            assert False

    def test_integration_dane_get_ca_certificate_for_identity_fail_valid(self):
        """Test failure to get a CA certificate for a valid identity name."""
        id_name = rsa_identity_name
        cert = self.get_dyn_asset("{}.cert.pem".format(id_name))
        with pytest.raises(ValueError):
            DANE.get_ca_certificate_for_identity(id_name, cert)
            assert False

    def test_integration_dane_get_ca_certificate_for_identity_fail_invalid(self):
        """Test failure to get a CA certificate for an invalid identity name."""
        id_name = "123.testing.device.example.com"
        aki = "aa-bc-de-00-12-34"
        with pytest.raises(ValueError):
            DANE.get_ca_certificate_for_identity(id_name, aki)
            assert False

    def test_integration_dane_get_ca_certificate_for_identity_success(self, requests_mock):
        """Test getting a CA certificate for an identity name."""
        for id_name in identity_names:
            id_cert = self.get_dyn_asset("{}.cert.pem".format(id_name))
            aki = DANE.get_authority_key_id_from_certificate(id_cert)
            ca_certificate = self.get_dyn_asset(ca_certificate_name)
            requests_mock.get("https://device.example.net/ca/{}.pem".format(aki), 
                              content=ca_certificate)
            retrieved = DANE.get_ca_certificate_for_identity(id_name, id_cert)
            assert retrieved == ca_certificate
    
    def test_integration_dane_authenticate_tlsa_pkix_cd(self, requests_mock):
        """Test successful authentication of pkix-cd."""
        for id_name in identity_names:
            entity_certificate = self.get_dyn_asset("{}.cert.pem".format(id_name))
            aki = DANE.get_authority_key_id_from_certificate(entity_certificate)
            x509_obj = DANE.build_x509_object(entity_certificate)
            ca_certificate = self.get_dyn_asset("ca.example.net.cert.pem")
            requests_mock.get("https://device.example.net/ca/{}.pem".format(aki), 
                              content=ca_certificate)
            cert_bytes = x509_obj.public_bytes(encoding=serialization.Encoding.DER)
            certificate_association = binascii.hexlify(cert_bytes).decode()
            tlsa_record = {"certificate_usage": 4, "selector": 0, "matching_type": 0, 
                           "certificate_association": certificate_association}
            tlsa_record["dnssec"] = False
            assert DANE.authenticate_tlsa(id_name, tlsa_record) is None

    def test_integration_dane_authenticate_tlsa_pkix_cd_fail(self, requests_mock):
        """Test failed authentication of pkix-cd."""
        for id_name in identity_names:
            entity_certificate = self.get_dyn_asset("{}.cert.pem".format(id_name))
            aki = DANE.get_authority_key_id_from_certificate(entity_certificate)
            x509_obj = DANE.build_x509_object(entity_certificate)
            ca_certificate = self.get_dyn_asset("{}.cert.pem".format(id_name))
            requests_mock.get("https://device.example.net/ca/{}.pem".format(aki),
                              content=ca_certificate)
            cert_bytes = x509_obj.public_bytes(encoding=serialization.Encoding.DER)
            certificate_association = binascii.hexlify(cert_bytes).decode()
            tlsa_record = {"certificate_usage": 4, "selector": 0, "matching_type": 0, 
                           "certificate_association": certificate_association}
            tlsa_record["dnssec"] = False
            with pytest.raises(TLSAError):
                DANE.authenticate_tlsa(id_name, tlsa_record)
                assert False

    def test_integration_dane_authenticate_tlsa_ee_fail(self, requests_mock):
        """Test failed authentication of ee cert."""
        for id_name in identity_names:
            entity_certificate = self.get_dyn_asset("{}.cert.pem".format(id_name))
            x509_obj = DANE.build_x509_object(entity_certificate)
            cert_bytes = x509_obj.public_bytes(encoding=serialization.Encoding.DER)
            certificate_association = binascii.hexlify(cert_bytes).decode()
            tlsa_record = {"certificate_usage": 4, "selector": 1, "matching_type": 1, 
                           "certificate_association": certificate_association}
            tlsa_record["dnssec"] = False
            with pytest.raises(TLSAError):
                DANE.authenticate_tlsa(id_name, tlsa_record)
                assert False

    def test_integration_dane_match_ski_aki(self):
        """Test matching the AKI of a cert to the SKI of its signing CA."""
        for id_name in identity_names:
            ee_cert = self.get_dyn_asset("{}.cert.pem".format(id_name))
            ca_cert = self.get_dyn_asset("ca.example.net.cert.pem")
            ee_aki = DANE.get_authority_key_id_from_certificate(ee_cert)
            ca_ski = DANE.get_subject_key_id_from_certificate(ca_cert)
            assert ee_aki == ca_ski
