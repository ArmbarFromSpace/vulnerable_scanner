# Why? Import exact spec names from checks.py
from .checks import check_security_headers, check_https, check_server_fingerprint, check_directory_listing, check_basic_xss, check_basic_sqli
# Why? * only grabs these—no old a01 etc. (fixes AttributeError)
__all__ = ['check_security_headers', 'check_https', 'check_server_fingerprint',
           'check_directory_listing', 'check_basic_xss', 'check_basic_sqli']
