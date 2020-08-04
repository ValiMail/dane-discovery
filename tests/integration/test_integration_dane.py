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

    def test_integration_dane_get_tlsa_records_noexist(self):
        """Test failure handling for nonexistent records."""
        test_dns_name = "_443._tcp.example.net"
        mock_resolver = dns.resolver
        mock_resolver.resolve = MagicMock(return_value=FakeTLSAEmptyAnswer())
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
