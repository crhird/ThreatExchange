#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Wrapper around the URL MD5 signal types.
"""

import hashlib

from threatexchange.signal_type import signal_base
from threatexchange import common


class UrlMD5Signal(signal_base.SimpleSignalType, signal_base.TextHasher):
    """
    Simple signal type for URL MD5s.
    """

    INDICATOR_TYPE = "HASH_URL_MD5"

    @classmethod
    def hash_from_str(cls, url: str) -> str:
        encoded_url = common.normalize_url(url)
        url_hash = hashlib.md5(encoded_url)
        return url_hash.hexdigest()
