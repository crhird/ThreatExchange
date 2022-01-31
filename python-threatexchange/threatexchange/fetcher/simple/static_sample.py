# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
The fetcher is the component that talks to external APIs to get and put signals

@see SignalExchangeAPI
"""


from dataclasses import dataclass
import itertools
import typing as t
import json

from threatexchange.signal_type.pdq import PdqSignal
from threatexchange.signal_type.pdq_ocr import PdqOcrSignal
from threatexchange.signal_type.md5 import VideoMD5Signal
from threatexchange.signal_type.raw_text import RawTextSignal
from threatexchange.signal_type.signal_base import SignalType
from threatexchange.signal_type.url import URLSignal
from threatexchange.signal_type.trend_query import TrendQuery, TrendQuerySignal

from threatexchange.fetcher import fetch_state as state
from threatexchange.fetcher.collab_config import CollaborationConfigBase
from threatexchange.fetcher.fetch_api import SignalExchangeAPI

from threatexchange.fetcher.simple.state import (
    SimpleFetchDelta,
)


class StaticSampleSignalExchangeAPI(SignalExchangeAPI):
    """
    Return a static set of sample data for demonstration.
    """

    def fetch_once(
        self,
        _collab: CollaborationConfigBase,
        _checkpoint: t.Optional[state.FetchCheckpointBase],
    ) -> SimpleFetchDelta:

        pdqs = [_signal(PdqSignal, s) for s in PdqSignal.get_examples()]
        pdq_ocrs = [_signal(PdqOcrSignal, s) for s in PdqOcrSignal.get_examples()]
        vmd5s = [_signal(VideoMD5Signal, s) for s in VideoMD5Signal.get_examples()]
        urls = [_signal(URLSignal, s) for s in URLSignal.get_examples()]
        text = [_signal(RawTextSignal, s) for s in RawTextSignal.get_examples()]
        trend_query = [_signal(TrendQuery, s) for s in TrendQuerySignal.get_examples()]

        return SimpleFetchDelta(
            dict(itertools.chain((pdqs, pdq_ocrs, vmd5s, urls, text, trend_query))),
            state.FetchCheckpointBase(),
        )


def _signal(
    sig_cls, ind: str
) -> t.Tuple[t.Tuple[t.Type[SignalType], str], state.SignalOpinion]:
    return (sig_cls, ind), state.SignalOpinion.get_trivial()
