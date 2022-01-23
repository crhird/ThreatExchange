#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Wrapper around the Photo PDQ signal type.
"""

from signal import signal
import typing as t
import pathlib
import warnings

from . import signal_base
from threatexchange.hashing.pdq_utils import simple_distance


def _raise_pillow_warning():
    warnings.warn(
        "PDQ from raw image data requires Pillow and pdqhash to be installed; install threatexchange with the [pdq_hasher] extra to use them",
        category=UserWarning,
    )


class PdqSignal(signal_base.SimpleSignalType, signal_base.BytesHasher):
    """
    PDQ is an open source photo similarity algorithm.

    Unlike MD5s, which are sensitive to single pixel differences, PDQ has
    a concept of "distance" and can detect when content is visually similar.
    This property tends to make it much more effective at finding images that
    a human would claim are the same, but also opens the door for false
    positives.

    Which distance to use can differ based on the type of content being
    searched for. While the PDQ documentation suggests certain thresholds,
    they can sometimes vary depending on what you are comparing against.
    """

    INDICATOR_TYPE = "HASH_PDQ"
    TYPE_TAG = "media_type_photo"

    # This may need to be updated (TODO make more configurable)
    # Hashes of distance less than or equal to this threshold are considered a 'match'
    PDQ_CONFIDENT_MATCH_THRESHOLD = 31

    @classmethod
    def compare_hash(cls, hash1: str, hash2: str) -> signal_base.HashComparisonResult:
        dist = simple_distance(hash1, hash2)
        return signal_base.HashComparisonResult.from_dist(
            dist, cls.PDQ_CONFIDENT_MATCH_THRESHOLD
        )

    @classmethod
    def hash_from_file(cls, file: pathlib.Path) -> str:
        try:
            from threatexchange.hashing.pdq_hasher import pdq_from_file
        except:
            _raise_pillow_warning()
            return ""
        pdq_hash, _quality = pdq_from_file(file)
        return pdq_hash

    @classmethod
    def hash_from_bytes(self, bytes_: bytes) -> str:
        try:
            from threatexchange.hashing.pdq_hasher import pdq_from_bytes
        except:
            _raise_pillow_warning()
            return ""
        pdq_hash, quality = pdq_from_bytes(bytes_)
        return pdq_hash
