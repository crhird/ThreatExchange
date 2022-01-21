# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved


from dataclasses import dataclass, field
import typing as t
from threatexchange.fetcher.fetch_api import SignalExchangeAPI

from threatexchange.signal_type.signal_base import SignalType
from threatexchange.fetcher import fetch_state
from threatexchange.fetcher.collab_config import CollaborationConfigBase


@dataclass
class SimpleFetchedSignalData(fetch_state.FetchedSignalMetadata):
    """
    Append + replace opinions by owner ID

    If you add any fields, make sure they are merged as well.
    """

    opinions: t.List[fetch_state.SignalOpinion] = field(default_factory=list)

    def get_as_opinions(self) -> t.List[fetch_state.SignalOpinion]:
        return self.opinions

    def merge(self, newer: "SimpleFetchedSignalData") -> None:
        """Assumes apppend, with merge on owner ID"""
        if not self.opinions or not newer.opinions:
            return

        by_owner = {o.owner_id: o for o in self.opinions}
        self.opinions = [by_owner.get(o.owner_id, o) for o in self.opinions]


@dataclass
class SimpleFetchDelta(fetch_state.FetchDeltaBase):
    """
    A simpler merger based on type (SignalType.get_name()) and str

    If the record is set to None, this indicates the record should be
    deleted if it exists.
    """

    updates: t.Dict[t.Tuple[str, str], t.Optional[SimpleFetchedSignalData]]
    checkpoint: fetch_state.FetchCheckpointBase

    def merge(self, newer: "SimpleFetchDelta"):
        for k, v in newer.updates.items():
            if v is None:
                self.updates.pop(k, None)
            elif k in self.updates:
                self.updates[k].merge(v)
            else:
                self.updates[k] = v
        self.checkpoint = newer.checkpoint

    def record_count(self) -> int:
        return len(self.updates)

    def next_checkpoint(self) -> fetch_state.FetchCheckpointBase:
        return self.checkpoint


class SimpleFetchedStateStore(fetch_state.FetchedStateStoreBase):
    """
    Standardizes on merging on (type, indicator), merges in memory.

    The entirety of the state is assumped to fit in a SimpleFetchDelta
    object or child class.
    """

    def __init__(
        self,
        api_cls: SignalExchangeAPI,
    ) -> None:
        self.api_cls = api_cls
        self._state = None
        self._dirty = False
        self._id_map = None

    def _read_state_as_delta(
        self,
        collab_name: str,
    ) -> SimpleFetchDelta:
        raise NotImplementedError

    def _write_state_as_delta(self, collab_name: str, delta: SimpleFetchDelta) -> None:
        raise NotImplementedError

    def get_checkpoint(
        self, collab: CollaborationConfigBase
    ) -> fetch_state.FetchCheckpointBase:
        return self.in_memory_state.checkpoint

    @property
    def in_memory_state(self):
        if self._state is None:
            self._state = self._read_state_as_delta()
            assert self._state is not None
            self._id_map = None
        return self._state

    def merge(self, collab: CollaborationConfigBase, delta: SimpleFetchDelta) -> None:
        """
        Merge a FetchDeltaBase into the state.

        At the implementation's discretion, it may call flush() or the
        equivalent work.
        """

        state = self.in_memory_state

        if delta.record_count() == 0 and delta.checkpoint in (None, state.checkpoint):
            return  # No op update?
        state.merge(delta)
        self._dirty = True

    def flush(self):
        if not self._dirty:
            return
        self._write_state_as_delta(self._state)
        self._dirty = False

    def get_for_signal_type(
        self, signal_type: t.Type[SignalType]
    ) -> t.List[t.Tuple[str, int]]:
        # TODO this is stored dumbly
        type_str = SignalType.get_name()
        return [
            (indicator, s.id)
            for (ind_type_str, indicator), s in self.in_memory_state.updates.items()
        ]

    def get_metadata_from_id(
        self, metadata_id: int
    ) -> t.Optional[fetch_state.FetchedSignalMetadata]:
        """
        Fetch the metadata from an ID
        """
        if self._id_map is None:
            self._id_map = {v.id: v for v in self.in_memory_state.values()}
        return self._id_map.get(metadata_id)


@dataclass
class SimpleFetchDeltaWithSyntheticID(fetch_state.FetchDeltaBase):
    """
    A version of fetch delta that creates its own IDs on merge.

    Only the delta that is being merge into generates IDs, and is
    assumed to be initially empty.

    i.e.

    >>> will_generate_ids = SimpleFetchDeltaWithSyntheticID({})
    >>> assumed_not_to_have_ids = SimpleFetchDeltaWithSyntheticID({"test", "test": val})
    >>> will_generate_ids.merge(assumed_not_to_have_ids)

    >>> assumed_not_to_have_ids.updates["test", "test"]
    0
    >>> will_generate_ids.updates["test", "test"]
    1
    >>> assumed_not_to_have_ids.merge(will_generate_ids)
    AssertionError
    """

    updates: t.Dict[
        t.Tuple[str, str],
        t.Optional[SimpleFetchedSignalData],
    ]
    # Shadow checkpoint to keep arguments in same relative order
    checkpoint: fetch_state.FetchCheckpointBase
    last_assigned_id: int = 0

    @classmethod
    def from_simple_opinons(
        cls,
        signal_type: t.Type[SignalType],
        signal_strs: t.Iterable[str],
        categorty: fetch_state.SignalOpinionCategory = fetch_state.SignalOpinionCategory.TRUE_POSITIVE,
    ) -> "SimpleFetchDeltaWithSyntheticID":
        return cls(
            {
                (signal_type.get_name(), signal_str): SimpleFetchedSignalData([])
                for signal_str in signal_strs
            }
        )

    def merge(self, newer: "SimpleFetchDeltaWithSyntheticID") -> None:
        assert (
            not self.last_assigned_id or not self.updates
        ), "Non-empty base with no ids"
        for k, v in newer.updates.items():
            assert not v.id, "newer delta already has IDs"
            if v is None:
                self.updates.pop(k, None)
            elif k in self.updates:
                self.updates[k].merge(v)
            else:
                self.last_assigned_id += 1
                v.id = self.last_assigned_id
                self.updates[k] = v
        self.checkpoint = newer.checkpoint

    def record_count(self) -> int:
        return len(self.updates)

    def next_checkpoint(self) -> fetch_state.FetchCheckpointBase:
        return self.checkpoint
