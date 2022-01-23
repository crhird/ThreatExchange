# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Local storage and configuration for the CLI.

The CLI and Hasher-Matcher-Actioner are roughly parallel, but this isn't a 
scalable service running on AWS. Instead, we have all of our state in
a file (likely ~/.threatexchange)
"""

from importlib.resources import path
import typing as t
import json
import pathlib
import functools
from threatexchange import content_type

from threatexchange.fetcher import collab_config
from threatexchange.fetcher.fetch_api import SignalExchangeAPI
from threatexchange.content_type import content_base
from threatexchange.content_type import text, video, photo, pdf, url
from threatexchange.signal_type import signal_base
from threatexchange.meta import FunctionalityMapping


FETCH_STATE_DIR_NAME = "fetched_state"
COLLABORATION_CONFIG_DIR_NAME = "collaborations"
INDEX_STATE_DIR_NAME = "index"
CONFIG_FILENAME = "config.json"


class CliState(collab_config.CollaborationConfigStoreBase):
    """
    A wrapper around stateful information stored for the CLI.

    Everything is just in a single file (usually ~/.threatexchange).
    """

    def __init__(
        self, dir: pathlib.Path, fetch_types: t.List[t.Type[SignalExchangeAPI]]
    ):
        if not dir.exists():
            dir.mkdir(parents=True)
        assert dir.is_dir()
        self._dir = dir

        self._fetch_types = fetch_types
        self._name_to_ctype = {
            ft.get_name(): ft.get_checkpoint_cls for ft in fetch_types
        }
        self._ctype_to_name = {v: k for k, v in self._name_to_ctype}

    @property
    def collab_dir(self) -> pathlib.Path:
        return self._dir / COLLABORATION_CONFIG_DIR_NAME

    def path_for_config(
        self, config: collab_config.CollaborationConfigBase
    ) -> pathlib.Path:
        api_name = self._ctype_to_name[config.__class__]
        return self.collab_dir / pathlib.Path(f"{config.name}.{api_name}.json")

    def get_all(self) -> t.List[collab_config.CollaborationConfigBase]:
        """
        Get all CollaborationConfigs, already resolved to the correct type
        """
        collab_dir = self.collab_dir
        if not collab_dir.exists():
            return []

        ret = []
        for f in collab_dir.glob("*.json"):
            if not f.is_file():
                continue
            ctype = self._name_to_ctype.get(f.name.spit(".")[-2])
            if ctype is None:
                continue
            with f.open() as fp:
                content = json.load(fp)
            # ret.append(ctype.from_json(content))
        return ret

    def update_collab(self, collab: collab_config.CollaborationConfigBase) -> None:
        """Create or update a collaboration"""
        path = self.path_for_config(collab)
        # with path.open("w") as fp:
        #     json.dumps(collab.as_json())

    def delete_collab(self, collab: collab_config.CollaborationConfigBase) -> None:
        """Delete a collaboration"""
        self.path_for_config(collab).unlink(missing_ok=True)


class CLISettings:
    """
    A God object for all miscellanious persisted state to make the CLI work
    """

    def __init__(self, mapping: FunctionalityMapping) -> None:
        self._mapping = mapping

    def get_all_content_types(self) -> t.List[t.Type[content_base.ContentType]]:
        return list(self._mapping.signal_and_content.content_by_name.values())

    def get_content_type(self, name: str) -> t.Type[content_base.ContentType]:
        return self._mapping.signal_and_content.content_by_name[name]

    def get_all_signal_types(self) -> t.List[t.Type[signal_base.SignalType]]:
        return list(self._mapping.signal_and_content.signal_type_by_name.values())

    def get_signal_type(self, name: str) -> t.Type[signal_base.SignalType]:
        return self._mapping.signal_and_content.signal_type_by_name[name]

    def get_signal_types_for_content(
        self, content_type: t.Type[content_base.ContentType]
    ) -> t.List[signal_base.SignalType]:
        # TODO - reimplement this
        supported_signals = set(self.get_all_signal_types())
        return [s for s in content_type.get_signal_types() if s in supported_signals]
