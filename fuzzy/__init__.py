"""
fuzzy - by æ’’
educational penetration testing tool for authorized environments only
"""
from .core import fuzzyRequester, fuzzyPayloads, fuzzyFuzzer


__version__ = "1.0.0"
__author__ = "caelok"

__all__ = [
    'fuzzyRequester',
    'fuzzyPayloads', 
    'fuzzyFuzzer'
]


VERSION_INFO = {
    'version': __version__,
    'author': __author__,
    'supported_python': '3.8+',
    'created': 'june 2025',
    'purpose': 'educational penetration testing and security research'
}


def get_version_info():
    """return version and library information"""
    return VERSION_INFO


def print_banner():
    """print fuzzy banner with sophisticated design"""
    banner = f"""

    """
    print(banner)


import os
if not os.environ.get('fuzzy_NO_BANNER'):
    print_banner()
