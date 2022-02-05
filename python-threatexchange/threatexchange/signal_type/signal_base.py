#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Core abstractions for signal types.
"""

import pathlib
import pickle
import typing as t

from threatexchange import common
from threatexchange.content_type import content_base
from threatexchange.signal_type import index


class HashComparisonResult(t.NamedTuple):
    match: bool
    distance: int

    @classmethod
    def from_match(cls, dist: int = 0) -> "HashComparisonResult":
        return cls(True, dist)

    @classmethod
    def from_no_match(cls, dist: int = 1) -> "HashComparisonResult":
        return cls(False, dist)

    @classmethod
    def from_dist(cls, dist: int, threshold: int) -> "HashComparisonResult":
        return cls(dist <= threshold, dist)

    @classmethod
    def from_bool(cls, matches: bool) -> "HashComparisonResult":
        return cls(matches, int(matches))


class SignalType:
    """
    Abstraction for different signal types.

    A signal type is an intermediate representation of content that can be used
    to match against similar or identical content. Sometimes called a "hash"
    type.

    This class additionally helps translates ThreatDescriptors into the correct
    representation to do matching, as well as serialize that representation
    into a compact form.
    """

    @classmethod
    def get_name(cls):
        """A compact name in lower_with_underscore style (used in filenames)"""
        return common.class_name_to_human_name(cls.__name__, "Signal")

    @classmethod
    def get_content_types(self) -> t.List[t.Type[content_base.ContentType]]:
        """Which content types this Signal applies to (usually just one)"""
        raise NotImplementedError

    @classmethod
    def get_index_cls(cls) -> t.Type[index.SignalTypeIndex]:
        """Return the index class that handles this signal type"""
        return TrivialSignalTypeIndex

    @classmethod
    def compare_hash(cls, hash1: str, hash2: str) -> HashComparisonResult:
        """
        Compare the distance of two hashes, the key operation for matching.

        Note that this can just be a reference/helper, and the efficient
        version of the algorithm can live in the index class.
        """
        raise NotImplementedError

    @classmethod
    def validate_hash(cls, hash1: str) -> bool:
        """
        Returns true if this appears to be a serialized signal for this type
        """
        return True

    @staticmethod
    def get_examples() -> t.List[str]:
        """
        @see threatexchange.fetcher.simple.static_sample
        """
        return []


class TextHasher:
    """
    This class can turn text into intermediary representations (hashes)
    """

    @classmethod
    def hash_from_str(cls, text: str) -> str:
        """Get a string representation of the hash from a string"""
        raise NotImplementedError

    @classmethod
    def hash_from_file(cls, file: pathlib.Path) -> str:
        return cls.hash_from_bytes(file.read_text())


class TrivialTextHasher(TextHasher):
    """The text == the hash"""

    @classmethod
    def hash_from_str(cls, content: str) -> str:
        return content


class MatchesStr:
    @classmethod
    def matches_str(cls, signal: str, haystack: str) -> HashComparisonResult:
        """
        Compare the distance of two hashes, the key operation for matching.

        Note that this can just be a reference/helper, and the efficient
        version of the algorithm can live in the index class.
        """
        raise NotImplementedError


class FileHasher:
    """
    This class can hash files.

    If also inheiriting from StrHasher, put this second in the inheiretence
    to prefer file hashing to reading the file in as a Str.
    """

    @classmethod
    def hash_from_file(cls, file: pathlib.Path) -> str:
        """Get a string representation of the hash from a file"""
        raise NotImplementedError


class BytesHasher(FileHasher):
    """
    This class can hash bytes.
    """

    @classmethod
    def hash_from_bytes(cls, bytes_: bytes) -> str:
        """Get a string representation of the hash from bytes."""
        raise NotImplementedError

    @classmethod
    def hash_from_file(cls, file: pathlib.Path) -> str:
        return cls.hash_from_bytes(file.read_bytes())


class SimpleSignalType(SignalType):
    """
    Dead simple implementation for loading/storing a SignalType.

    Assumes that the signal type can easily merge on a string.
    """

    INDICATOR_TYPE: t.Union[str, t.Tuple[str, ...]] = ()
    TYPE_TAG: t.Optional[str] = None

    @classmethod
    def indicator_applies(cls, indicator_type: str, tags: t.List[str]) -> bool:
        types = cls.INDICATOR_TYPE
        if isinstance(cls.INDICATOR_TYPE, str):
            types = (cls.INDICATOR_TYPE,)
        if indicator_type not in types:
            return False
        if cls.TYPE_TAG is not None:
            return cls.TYPE_TAG in tags
        return True

    @classmethod
    def compare_hash(cls, hash1: str, hash2: str) -> HashComparisonResult:
        return HashComparisonResult.from_bool(hash1 == hash2)


class TrivialSignalTypeIndex(index.SignalTypeIndex):
    """
    Index that does only exact matches and serializes with pickle
    """

    def __init__(self) -> None:
        self.state: t.Dict[str, t.List[t.Any]] = {}

    def query(self, hash: str) -> t.List[index.IndexMatch[index.T]]:
        return [index.IndexMatch(0, meta) for meta in self.state.get(hash, [])]

    def add(self, vals: t.Iterable[t.Tuple[str, t.Any]]) -> None:
        for k, val in vals:
            l = self.state.get(k)
            if not l:
                l = []
                self.state[k] = l
            l.append(val)

    @classmethod
    def build(cls, vals: t.Iterable[t.Tuple[str, t.Any]]):
        ret = cls()
        ret.add(vals=vals)
        return ret

    def serialize(self, fout: t.BinaryIO):
        pickle.dump(self, fout)

    @classmethod
    def deserialize(cls, fin: t.BinaryIO):
        return pickle.load(fin)


class TrivialLinearSearchIndex(index.SignalTypeIndex):
    """
    Index that does a linear search and serializes with pickle

    O(n) is the best n, clearly.
    """

    # You'll have to override with each usecase
    _SIGNAL_TYPE: t.Type[SignalType]

    def __init__(self) -> None:
        self.state: t.List[(str, index.T)] = []

    def query(self, query_hash: str) -> t.List[index.IndexMatch[index.T]]:
        ret = []
        for hash, payload in self.state:
            res = self._SIGNAL_TYPE.compare_hash(hash, query_hash)
            if res.match:
                ret.append(index.IndexMatch(res.distance, payload))
        return ret

    def add(self, vals: t.Iterable[t.Tuple[str, index.T]]) -> None:
        self.state.extend(vals)

    @classmethod
    def build(cls, vals: t.Iterable[t.Tuple[str, index.T]]):
        ret = cls()
        ret.add(vals)
        return ret

    def serialize(self, fout: t.BinaryIO):
        pickle.dump(self, fout)

    @classmethod
    def deserialize(cls, fin: t.BinaryIO):
        return pickle.load(fin)
