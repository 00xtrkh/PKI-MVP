"""Revocation / CRL service."""

def ensure_empty_crl(*, root_ca=None, force=False, settings=None):
    raise NotImplementedError

def list_revoked():
    raise NotImplementedError

def revoke_serial(serial_number, **kwargs):
    raise NotImplementedError

def revoke_by_cn(common_name, **kwargs):
    raise NotImplementedError

def load_crl():
    raise NotImplementedError

def is_revoked(serial_number):
    raise NotImplementedError
