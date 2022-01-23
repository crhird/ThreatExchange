#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Wrapper around the URL signal type.
"""

from threatexchange.signal_type import signal_base


class URLSignal(signal_base.SimpleSignalType, signal_base.TrivialTextHasher):
    """
    Wrapper around URL links, such as https://github.com/
    """

    INDICATOR_TYPE = ("URI", "RAW_URI")
