#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
A wrapper around loading and storing ThreatExchange data from files.

There are a few categories of state that this wraps:
  1. Checkpoints - state about previous fetches
  2. Collaboration Indicator Dumps - Raw output from threat_updates
  3. Index state - serializations of indexes for SignalType
"""

from enum import Enum
import json
import pathlib
import typing as t
import dataclasses
import logging

import dacite
from build.lib.threatexchange.signal_type.index import SignalTypeIndex
from build.lib.threatexchange.signal_type.signal_base import SignalType

from threatexchange.cli.exceptions import CommandError
from threatexchange.fetcher.collab_config import CollaborationConfigBase
from threatexchange.fetcher.fetch_state import FetchCheckpointBase
from threatexchange.fetcher.simple import state as simple_state
from threatexchange.fetcher.fetch_api import SignalExchangeAPI
from threatexchange.signal_type import signal_base
from threatexchange.signal_type import index


class FetchCheckpoint(t.NamedTuple):
    last_full_fetch: float
    last_fetch: float


class Dataset:

    EXTENSION = ".te"


class CliIndexStore:

    FILE_EXTENSION = ".index"

    def __init__(self, indice_dir: pathlib.Path) -> None:
        self.dir = indice_dir

    def get_available(self) -> t.List[str]:
        return [
            str(f)[-len(self.FILE_EXTENSION)]
            for f in self.dir.glob(f"*{self.FILE_EXTENSION}")
        ]

    def clear(self, only_types: t.Optional[t.List[t.Type[SignalType]]] = None) -> None:
        only_names = None
        if only_types is not None:
            only_names = {st.get_name() for st in only_types}
        for file in self.dir.glob(f"*{self.FILE_EXTENSION}"):
            if (
                only_names is None
                or str(file)[: -len(self.FILE_EXTENSION)] in only_names
            ):
                logging.info("Removing index %s", file)
                file.unlink()

    def _index_file(self, signal_type: signal_base.SignalType) -> pathlib.Path:
        return self.dir / f"{signal_type.get_name()}{self.FILE_EXTENSION}"

    def store_index(
        self, signal_type: signal_base.SignalType, index: SignalTypeIndex
    ) -> None:
        assert signal_type.get_index_cls() == index.__class__
        path = self._index_file(signal_type)
        with path.open("wb") as fout:
            index.serialize(fout)

    def load_index(
        self, signal_type: signal_base.SignalType
    ) -> t.Optional[index.SignalTypeIndex]:
        path = self._index_file(signal_type)
        if not path.exists():
            return None
        with path.open("rb") as fin:
            return signal_type.get_index_cls().deserialize(fin)


class CliSimpleState(simple_state.SimpleFetchedStateStore):

    JSON_CHECKPOINT_KEY = "checkpoint"
    JSON_RECORDS_KEY = "records"

    def __init__(
        self, api_cls: t.Type[SignalExchangeAPI], fetched_state_dir: pathlib.Path
    ) -> None:
        super().__init__(api_cls)
        self.dir = fetched_state_dir

    def collab_file(self, collab_name: str) -> pathlib.Path:
        return self.dir / f"{collab_name}.state.json"

    def clear(self, collab: CollaborationConfigBase) -> None:
        file = self.collab_file(collab.name)
        if file.is_file():
            logging.info("Removing %s", file)
            file.unlink(missing_ok=True)
        if next(file.parent.iterdir(), None) is None:
            logging.info("Removing directory %s", file.parent)
            file.parent.rmdir()

    def _read_state(
        self,
        collab_name: str,
    ) -> t.Optional[
        t.Tuple[
            t.Dict[str, t.Dict[str, simple_state.SimpleFetchedSignalMetadata]],
            FetchCheckpointBase,
        ]
    ]:
        file = self.collab_file(collab_name)
        if not file.is_file():
            return None
        try:
            with file.open("r") as f:
                json_dict = json.load(f)

            checkpoint = dacite.from_dict(
                data_class=self.api_cls.get_checkpoint_cls(),
                data=json_dict[self.JSON_CHECKPOINT_KEY],
                config=dacite.Config(cast=[Enum]),
            )
            records = json_dict[self.JSON_RECORDS_KEY]

            # Minor stab at lowering memory footprint by converting kinda
            # inline
            for stype in list(records):
                records[stype] = {
                    signal: dacite.from_dict(
                        data_class=self.api_cls.get_record_cls(),
                        data=json_record,
                        config=dacite.Config(cast=[Enum]),
                    )
                    for signal, json_record in records[stype].items()
                }
            return records, checkpoint
        except Exception:
            logging.exception("Failed to read state for %s", collab_name)
            raise CommandError(
                f"Failed to read state for {collab_name}. "
                "You might have to delete it with `threatexchange fetch --clear`"
            )

    def _write_state(
        self,
        collab_name: str,
        updates_by_type: t.Dict[
            str, t.Dict[str, simple_state.SimpleFetchedSignalMetadata]
        ],
        checkpoint: FetchCheckpointBase,
    ) -> None:
        file = self.collab_file(collab_name)
        if not file.parent.exists():
            file.parent.mkdir(parents=True)

        record_sanity_check = next(
            (
                record
                for records in updates_by_type.values()
                for record in records.values()
            ),
            None,
        )

        if record_sanity_check is not None:
            assert (  # Not isinstance - we want exactly this class
                record_sanity_check.__class__ == self.api_cls.get_record_cls()
            ), (
                f"Record cls: want {self.api_cls.get_record_cls().__name__} "
                f"got {record_sanity_check.__class__.__name__}"
            )

        json_dict = {
            self.JSON_CHECKPOINT_KEY: dataclasses.asdict(checkpoint),
            self.JSON_RECORDS_KEY: {
                stype: {
                    s: dataclasses.asdict(record)
                    for s, record in signal_to_record.items()
                }
                for stype, signal_to_record in updates_by_type.items()
            },
        }
        with file.open("w") as f:
            json.dump(json_dict, f, indent=2)
