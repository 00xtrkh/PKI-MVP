"""Root CA service."""

def root_ca_exists():
    raise NotImplementedError

def initialize_root_ca(*, force=False, passphrase=None, settings=None):
    raise NotImplementedError

def ensure_root_ca(*, settings=None):
    raise NotImplementedError

def load_root_ca(*, passphrase=None):
    raise NotImplementedError
