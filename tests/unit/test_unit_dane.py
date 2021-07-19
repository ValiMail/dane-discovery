"""Test the DANE object."""
import os

import pytest

from dane_discovery.dane import DANE
from dane_discovery.exceptions import TLSAError


here_dir = os.path.dirname(os.path.abspath(__file__))
dyn_assets_dir = os.path.join(here_dir, "../fixtures/dynamic/")
rsa_identity_name = "rsa.air-quality-sensor._device.example.net"
ecc_identity_name = "ecc.air-quality-sensor._device.example.net"
identity_names = [rsa_identity_name, ecc_identity_name]


class TestUnitDane:
    """Unit tests for DANE."""

    def get_dyn_asset(self, asset_name):
        """Return the contents of a file from the dynamic assets dir."""
        asset_path = os.path.join(dyn_assets_dir, asset_name)
        with open(asset_path, "rb") as asset:
            return asset.read()

    def test_unit_dane_generate_tlsa_record(self):
        """Ensure that bytes are returned for matching type 0."""
        for identity_name in identity_names:
            certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
            result = DANE.generate_tlsa_record(3, 0, 0, certificate)
            assert isinstance(result, str)

    def test_unit_dane_generate_tlsa_record_bad(self):
        """Ensure that bad matching type raises ValueError."""
        for identity_name in identity_names:
            certificate = self.get_dyn_asset("{}.cert.pem".format(identity_name))
            with pytest.raises(TLSAError):
                DANE.generate_tlsa_record(3, 0, 3, certificate)
                assert False

    def test_unit_process_response(self):
        """Test parsing a response into named fields."""
        response = "name.example.com 123 IN TLSA 3 1 2 55F6DB74C524ACCA28B52C0BCFC28EEC4596F90D00C 596F90D0"
        cert_assoc = "55F6DB74C524ACCA28B52C0BCFC28EEC4596F90D00C596F90D0"
        processed = DANE.process_response(response)
        assert isinstance(processed, dict)
        assert processed["certificate_usage"] == 3
        assert processed["selector"] == 1
        assert processed["matching_type"] == 2
        assert processed["certificate_association"] == cert_assoc

    def test_unit_process_response_fail(self):
        """Test validation failure."""
        response = r"name.example.com 123 IN TLSA 3 1 2 55F6DB74C524ACCA28..\..\B52C0BCFC28EEC4596F90D00C 596F90D0"
        with pytest.raises(TLSAError) as err:
            DANE.process_response(response)
        assert "certificate association" in str(err)

    def test_unit_generate_url_for_ca_certificate(self):
        desired = "https://device.organization.example/.well-known/ca/a-k-i.pem"
        actual = DANE.generate_url_for_ca_certificate("device.organization.example", "a-k-i")
        assert desired == actual

    def test_unit_dane_validate_tlsa_fields(self):
        response = "name.example.com 123 IN TLSA 3 1 2 55F6DB74C524ACCA28B52C0BCFC28EEC4596F90D00C 596F90D0"
        assert DANE.validate_tlsa_fields(DANE.process_response(response)) is None

    def test_unit_dane_validate_tlsa_fields_fail_nocert(self):
        response = "name.example.com 123 IN TLSA 3 0 0 55F6DB74C524ACCA28B52C0BCFC28EEC4596F90D00C 596F90D0"
        with pytest.raises(TLSAError):
            DANE.validate_tlsa_fields(DANE.process_response(response))
