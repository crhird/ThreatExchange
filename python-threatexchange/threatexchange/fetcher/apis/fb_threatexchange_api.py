# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
SignalExchangeAPI impl for Facebook/Meta's ThreatExchange Graph API platform.

https://developers.facebook.com/programs/threatexchange
https://developers.facebook.com/docs/threat-exchange/reference/apis/
"""


import typing as t
import time
from dataclasses import dataclass
from pathlib import Path
from threatexchange.fetcher.simple.state import (
    SimpleFetchDelta,
    SimpleFetchedSignalMetadata,
)

from threatexchange.fetcher import fetch_state as state
from threatexchange.fetcher.fetch_api import SignalExchangeAPI
from threatexchange.fetcher.collab_config import (
    CollaborationConfigBase,
    DefaultsForCollabConfigBase,
)
from threatexchange.signal_type.signal_base import SignalType
from threatexchange.fb_threatexchange import api as tx_api


@dataclass
class FBThreatExchangeCollabConfig(
    CollaborationConfigBase, DefaultsForCollabConfigBase
):
    privacy_group: int
    app_token_override: t.Optional[str] = None


@dataclass
class FBThreatExchangeCheckpoint(state.FetchCheckpointBase):
    update_time: int
    last_fetch_time: int
    last_token: str

    def is_stale(self) -> bool:
        """Consider stale after 30d of not fetching"""
        return time.time() - self.last_fetch_time > 3600 * 24 * 30

    def get_progress_timestamp(self) -> t.Optional[int]:
        return self.update_time


@dataclass
class FBThreatExchangeIndicatorRecord(SimpleFetchedSignalMetadata):
    pass


class FBThreatExchangeSignalExchangeAPI(SignalExchangeAPI):
    def __init__(self, fb_app_token: t.Optional[str] = None) -> None:
        self.default_app_token = fb_app_token

    @classmethod
    def get_name(cls) -> str:
        return super().get_name()  # TODO: Check if needs impl

    @classmethod
    def get_checkpoint_cls(cls) -> t.Type[state.FetchCheckpointBase]:
        return FBThreatExchangeCheckpoint

    @classmethod
    def get_record_cls(cls) -> t.Type[FBThreatExchangeIndicatorRecord]:
        return FBThreatExchangeIndicatorRecord

    @classmethod
    def get_config_class(cls) -> t.Type[FBThreatExchangeCollabConfig]:
        return FBThreatExchangeCollabConfig

    def resolve_owner(self, id: int) -> str:
        # TODO - fetch app id from ThreatExchange
        raise NotImplementedError

    def get_own_owner_id(self, collab: FBThreatExchangeCollabConfig) -> int:
        token = collab.app_token_override or self.default_app_token
        assert token

    def fetch_once(
        self,
        supported_signal_types: t.List[t.Type[SignalType]],
        collab: CollaborationConfigBase,
        # None if fetching for the first time,
        # otherwise the previous FetchDelta returned
        checkpoint: t.Optional[state.FetchCheckpointBase],
    ) -> state.FetchDeltaBase:
        """
        Call out to external resources, pulling down one "batch" of content.

        Many APIs are a sequence of events: (creates/updates, deletions)
        In that case, it's important the these events are strictly ordered.
        I.e. if the sequence is create => delete, if the sequence is reversed
        to delete => create, the end result is a stored record, when the
        expected is a deleted one.
        """
        raise NotImplementedError

    def report_seen(
        self, s_type: SignalType, signal: str, metadata: state.FetchedStateStoreBase
    ) -> None:
        """
        Report that you observed this signal.

        This is an optional API, and places that use it should catch
        the NotImplementError.
        """
        raise NotImplementedError

    def report_opinion(
        self,
        collab: CollaborationConfigBase,
        s_type: t.Type[SignalType],
        signal: str,
        opinion: state.SignalOpinion,
    ) -> None:
        """
        Weigh in on a signal for this collaboration.

        Most implementations will want a full replacement specialization, but this
        allows a common interface for all uploads for the simplest usecases.

        This is an optional API, and places that use it should catch
        the NotImplementError.
        """
        raise NotImplementedError

    def report_true_positive(
        self,
        collab: CollaborationConfigBase,
        s_type: t.Type[SignalType],
        signal: str,
        metadata: state.FetchedSignalMetadata,
    ) -> None:
        """
        Report that a previously seen signal was a true positive.

        This is an optional API, and places that use it should catch
        the NotImplementError.
        """
        self.report_opinion(
            collab,
            s_type,
            signal,
            state.SignalOpinion(
                owner=self.get_own_owner_id(),
                category=state.SignalOpinionCategory.TRUE_POSITIVE,
                tags=[],
            ),
        )

    def report_false_positive(
        self,
        collab: CollaborationConfigBase,
        s_type: t.Type[SignalType],
        signal: str,
        _metadata: state.FetchedSignalMetadata,
    ) -> None:
        """
        Report that a previously seen signal is a false positive.

        This is an optional API, and places that use it should catch
        the NotImplementError.
        """
        self.report_opinion(
            collab,
            s_type,
            signal,
            state.SignalOpinion(
                owner=self.get_own_owner_id(),
                category=state.SignalOpinionCategory.FALSE_POSITIVE,
                tags=[],
            ),
        )

    @classmethod
    def get_config_class(cls) -> CollaborationConfigBase:
        return FBThreatExchangeCollabConfig

    def fetch_once(
        self,
        supported_signal_types: t.List[t.Type[SignalType]],
        collab: FBThreatExchangeCollabConfig,
        checkpoint: t.Optional[state.FetchCheckpointBase],
    ) -> state.FetchDeltaBase:
        """Fetch the whole file"""
        path = Path(collab.filename)
        assert path.exists(), f"No such file {path}"
        assert path.is_file(), f"{path} is not a file (is it a dir?)"

        # TODO - Support things other than just one item per line
        with path.open("r") as f:
            lines = f.readlines()

        updates = {}
        for line in lines:
            signal_type = collab.signal_type
            signal = line.strip()
            if signal_type is None:
                signal_type, _, signal = signal.partition(" ")
            if signal_type and signal:
                updates[signal_type, signal] = state.FetchedSignalMetadata()

        return SimpleFetchDelta(updates, state.FetchCheckpointBase(), done=True)

    def report_opinion(
        self,
        collab: FBThreatExchangeCollabConfig,
        s_type: t.Type[SignalType],
        signal: str,
        opinion: state.SignalOpinion,
    ) -> None:
        raise NotImplementedError
