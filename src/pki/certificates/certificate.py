"""CSR builders."""

def allocate_serial_number():
    raise NotImplementedError

def build_client_name(common_name, settings=None):
    raise NotImplementedError

def create_certificate_signing_request(private_key, common_name, settings=None):
    raise NotImplementedError

def csr_to_pem(csr):
    raise NotImplementedError

def load_csr_pem(pem_data):
    raise NotImplementedError
