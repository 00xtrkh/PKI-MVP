"""Certificate issuance service."""

def create_csr_for_common_name(common_name, *, settings=None):
    raise NotImplementedError

def submit_csr_pem(csr_pem):
    raise NotImplementedError

def list_csrs(*, status=None):
    raise NotImplementedError

def list_certificates(*, include_revoked=True):
    raise NotImplementedError

def get_certificate_by_serial(serial):
    raise NotImplementedError

def issue_certificate(**kwargs):
    raise NotImplementedError
