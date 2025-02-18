
import re

from .base import RegexBasedDetector


class ApiKeyDetector(RegexBasedDetector):
    """
    Scans for private keys.

    This checks for private keys by determining whether the denylisted
    lines are present in the analyzed string.
    """

    secret_type = 'Api Key'

    api_key_pattern = r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"

    denylist = [re.compile(api_key_pattern)]
