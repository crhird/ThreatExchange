#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Wrapper around the raw text signal type.
"""

import math
import pathlib
import typing as t

import Levenshtein

from threatexchange import common
from threatexchange.signal_type import signal_base
from threatexchange.signal_type import index


class RawTextSignal(signal_base.SimpleSignalType, signal_base.TextHasher):
    """
    Raw text signal is the same as raw text content: the exact text content.

    Unlike other formats like photos or videos, it is difficult to come
    up with non-reversable hashes of text information which are also effective
    at detecting similar content.
    """

    INDICATOR_TYPE = "TEXT_STRING"

    @classmethod
    def hash_from_str(cls, content: str) -> str:
        """Get a string representation of the hash from a string"""
        return common.normalize_string(content)

    @classmethod
    def compare_hash(cls, hash1: str, hash2: str) -> signal_base.HashComparisonResult:
        # Match considered if 95% match
        match_threshold = math.floor(len(hash1) * 0.05)

        ldiff = abs(len(hash1) - len(hash2))

        if ldiff > match_threshold:
            return signal_base.HashComparisonResult.no_match_result()

        distance = Levenshtein.distance(hash1, hash2)
        return signal_base.HashComparisonResult(distance <= match_threshold, distance)

    @classmethod
    def get_index_cls(cls) -> t.Type[index.SignalTypeIndex]:
        return LevenshteinLinearSearch

    @staticmethod
    def get_examples() -> t.List[str]:
        return [
            "The quick brown fox jumps over the lazy dog",
            (
                "We the People of the United States, in Order to form a more "
                "perfect Union, establish Justice, ensure domestic "
                "Tranquility, provide for the common defence, promote the "
                "general Welfare, and secure the Blessings of Liberty to "
                "ourselves and our Posterity, do ordain and establish this "
                "Constitution for the United States of America."
            ),
            "bball now?",
        ]


class LevenshteinLinearSearch(signal_base.TrivialLinearSearchIndex):
    _SIGNAL_TYPE = RawTextSignal
