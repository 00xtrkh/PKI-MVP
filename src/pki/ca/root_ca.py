"""Self-signed Root CA crypto."""

def create_self_signed_root_certificate(private_key, settings=None, not_before=None):
    raise NotImplementedError

def certificate_to_pem(certificate):
    raise NotImplementedError

def build_ca_name(settings=None):
    raise NotImplementedError
