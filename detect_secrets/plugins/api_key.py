"""
This code was extracted in part from
https://github.com/pre-commit/pre-commit-hooks. Using similar heuristic logic,
we adapted it to fit our plugin infrastructure, to create an organized,
concerted effort in detecting all type of secrets in code.

Copyright (c) 2014 pre-commit dev team: Anthony Sottile, Ken Struys

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
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
