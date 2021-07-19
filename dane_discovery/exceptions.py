"""Exceptions defined here."""


class TLSAError(Exception):
    """General TLSA error, details in ``self.message``."""

class PKIXError(Exception):
    """General PKIX error, details in ``self.message``."""
