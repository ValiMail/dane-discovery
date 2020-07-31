"""Exceptions defined here."""


class TLSAError(Exception):
    """General TLSA error, details in ``self.message``."""


class DIDNError(Exception):
    """General error, details in ``self.message``."""
