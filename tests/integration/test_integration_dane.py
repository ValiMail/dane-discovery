"""Test the DANE object."""
import binascii
import os

from cryptography.x509 import Certificate
import dns
import pytest
from unittest.mock import MagicMock

from dane_discovery.dane import DANE
from dane_discovery.exceptions import TLSAError


here_dir = os.path.dirname(os.path.abspath(__file__))
dyn_assets_dir = os.path.join(here_dir, "../fixtures/dynamic/")
identity_name = "abc123.air-quality-sensor._device.example.net"
tlsa_record_full = (
    "3 0 0 3082045130820339A003020102021444C9E6D133B2CAE"
    "0DE61A7270E A654CDAC8D1B4C300D06092A864886F70D01010B05003081B3310B30 090"
    "60355040613025553310B30090603550408130243413115301306 03550407130C53616E"
    "4672616E636973636F3111300F060355040A13 0876616C696D61696C311D301B0603550"
    "40B13144D794F7267616E69 7A6174696F6E616C556E6974311430120603550403130B76"
    "616C696D 61696C2043413110300E060355042913074561737952534131263024 06092A"
    "864886F70D01090116176173682E77696C736F6E4076616C69 6D61696C2E636F6D301E1"
    "70D3230303732353231323932395A170D32 30303830393231323932395A308196310B30"
    "09060355040613025553 310B300906035504080C0243413116301406035504070C0D536"
    "16E20 4672616E636973636F311B3019060355040A0C1241636D65204D616E 756661637"
    "47572696E673145304306035504030C3C62757474657266 6C792E6169722D7175616C69"
    "74792D73656E736F722E5F6D64657669 63652E61636D652D6D616E75666163747572696"
    "E672E6E6574308201 22300D06092A864886F70D01010105000382010F003082010A0282"
    "01 0100C67A51FFE125216051C925C82E12FAA903172AF13AA111234AB9 36460FA690B8"
    "7B15D349021CAE11A8595934EF663FE094D7218AF4F2 68F4EE32B6E45544CC0C7FDC711"
    "4B3D550B82888AFC5EC05A5F12E74 617BC4CC618A8008CCD31F5889232107BC10D45B3B"
    "5126897947B6A8 DEB2BAF3B1D3F99C3348732A7378CE1651C4F4F0F6AF19E7C52084D3 "
    "7C1034B1B5CD1C04E59650A33FFB1D1A304F36ABB8C09EA8CC17B40D D4D225CB4132750"
    "147BB3B24100F4902B8C6913B4D9647D4D112733E 2265F7F84286ABCA050BE2E5EC3075"
    "DC6D2B9ACEEFECF38230B2061E 8B6294842918CACE4FC0EEE4CA5C5F1D4F2FC1E262499"
    "9172A879A53 0258AED2D8370203010001A3783076300C0603551D130101FF040230 003"
    "0470603551D110440303E823C627574746572666C792E6169722D 7175616C6974792D73"
    "656E736F722E5F6D6465766963652E61636D65 2D6D616E75666163747572696E672E6E6"
    "574301D0603551D25041630 1406082B0601050507030106082B06010505070302300D06"
    "092A8648 86F70D01010B050003820101009ED906EBA7AF121AD5D88CBF3B2C4B B14675"
    "05A49CBD11FD0BA9325BA3E1D1A58D8134E4DCC2B3CDAC9D00 86DDC6CA21BB8DAC43EFA"
    "E9C87A024992DBD8A1EE18681ED4B32928E 8491CA495265D2125290AED01DFE89566859"
    "7AF793DDBD57E0543E0C A540B6BDBE4BA34CBB95499E3FBD63EAA92AE674BB951DA2982"
    "D669D 56E66E5A21BB3AB43DF31BDC65394C4E973FAA049BCF84970754B9C3 79472CE96"
    "B1CF2BCA45A8C17FC83B7D506A4590A1D1CDF2D89BADF48 43E06834EF1970F7CBDD4DDB"
    "1AAFCC53C6E0B50C5167ABBEE4820604 EB1CDE588AAA25190F811079BEE23284DA82719"
    "3B2ED40D0A0FDBF30 2F2B87E7318B28A59AC94FC029312FF817"
    )

tlsa_record_shorts = [
    "3 1 1 55F6DB74C524ACCA28B52C0BCFC28EEC4596F90D00C2056010AE7990 1B2EB049",
    "3 1 1 736A6032543CF64DE9D4CFBD5BDFFD329027FE1FE860B2396954A9D9 DB630FD1",
    "3 1 1 9D0062CA1CED50C2EB6785B9985B1B59ED3A14E9F27114BCC162F8AC FFEF8683"]


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


class FakeRR:
    """Fake a single TLSA RR."""

    def __init__(self, rr):
        """Initialize with one RR."""
        self.rr = rr

    def to_text(self):
        """Return the RR."""
        return self.rr


class FakeTLSALongAnswer:
    """Fake response for full answer."""

    def __init__(self):
        """Instantiate with one full TLSA RR."""
        self.rrset = [FakeRR(tlsa_record_full)]

    def __iter__(self):
        """Yield one by one."""
        for x in self.rrset:
            yield x


class FakeTLSAShortAnswer:
    """Fake response for SHA answers."""

    def __init__(self):
        """Instantiate with some SHA TLSA RRs."""
        self.rrset = [FakeRR(x) for x in tlsa_record_shorts]

    def __iter__(self):
        """Yield one by one."""
        for x in self.rrset:
            yield x


class FakeTLSAEmptyAnswer:
    """Fake response for empty result."""

    def __init__(self):
        """Instantiate with some SHA TLSA RRs."""
        self.rrset = []

    def __iter__(self):
        """Yield one by one."""
        raise dns.resolver.NXDOMAIN("yolo.")


class TestIntegrationDane:
    """Integration tests for DANE."""

    def get_dyn_asset(self, asset_name):
        """Return the contents of a file from the dynamic assets dir."""
        asset_path = os.path.join(dyn_assets_dir, asset_name)
        with open(asset_path, "rb") as asset:
            return asset.read()

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

    def test_integration_dane_get_tlsa_records_noexist(self):
        """Test failure handling for nonexistent records."""
        test_dns_name = "_443._tcp.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSAEmptyAnswer())
        with pytest.raises(TLSAError):
            DANE.get_tlsa_records(test_dns_name)
            assert False
        del mock_resolver.resolve

    def test_integration_dane_get_tlsa_records_noanswer(self):
        """Test failure handling for nonexistent records."""
        test_dns_name = "_443._tcp.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSAEmptyAnswer())
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        with pytest.raises(TLSAError):
            DANE.get_tlsa_records(test_dns_name)
            assert False
        del mock_resolver.resolve

    def test_integration_dane_get_tlsa_records_sha(self):
        """Process short records."""
        test_dns_name = "_443._tcp.www.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSAShortAnswer())
        result = DANE.get_tlsa_records(test_dns_name)
        del mock_resolver.resolve
        assert isinstance(result, list)

    def test_integration_dane_get_tlsa_records_cert(self):
        """Get the TLSA records from other test site."""
        test_dns_name = "butterfly.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSAShortAnswer())
        result = DANE.get_tlsa_records(test_dns_name)
        del mock_resolver.resolve
        assert isinstance(result, list)

    def test_integration_dane_get_tlsa_leaf_cert(self):
        """Get one TLSA record."""
        test_dns_name = "butterfly.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSALongAnswer())
        result = DANE.get_first_leaf_certificate(test_dns_name)
        del mock_resolver.resolve
        assert isinstance(result, dict)

    def test_integration_dane_get_tlsa_leaf_cert_convert_pem(self):
        """Get one TLSA record, convert to PEM."""
        test_dns_name = "butterfly.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSALongAnswer())
        cert = DANE.get_first_leaf_certificate(test_dns_name)
        del mock_resolver.resolve
        der_cert = DANE.certificate_association_to_der(cert["certificate_association"])  # NOQA
        pem = DANE.der_to_pem(der_cert)
        assert isinstance(pem, bytes)

    def test_integration_dane_get_tlsa_record_leaf_cert_none(self):
        """Get single TLSA record."""
        test_dns_name = "butterfly.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSAShortAnswer())
        result = DANE.get_first_leaf_certificate(test_dns_name)
        del mock_resolver.resolve
        assert result is None

    def test_integration_dane_generate_parse_tlsa_record(self):
        """Generate DANE record, attempt to parse."""
        certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
        generated = DANE.generate_tlsa_record(3, 0, 0, certificate)
        parsed = DANE.process_response(generated)
        assert DANE.validate_certificate(parsed["certificate_association"]) is None  # NOQA
        der_cert = binascii.unhexlify(parsed["certificate_association"])
        x5_obj = DANE.build_x509_object(der_cert)
        assert isinstance(x5_obj, Certificate)
