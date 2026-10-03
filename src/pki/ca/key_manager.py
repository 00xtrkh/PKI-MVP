"""RSA key helpers."""

def generate_rsa_private_key(key_size=None):
    raise NotImplementedError

def private_key_to_pem(private_key, passphrase=None):
    raise NotImplementedError

def load_private_key_pem(pem_data, passphrase=None):
    raise NotImplementedError

def get_public_key(private_key):
    raise NotImplementedError
