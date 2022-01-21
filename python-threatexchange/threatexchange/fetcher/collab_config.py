#!/usr/bin/env python
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

"""
Settings used to inform a fetcher what to fetch
"""

from dataclasses import dataclass
import typing as t


@dataclass
class CollaborationConfigBase:
    """
    Settings used to inform a fetcher what to fetch.

    Extend with any additional fields that you need to inform your API how
    and what to fetch.

    Management of persisting these is left to the specific platform
    (i.e. CLI or HMA).
    """

    name: str
    enabled: bool  # Whether to match this or not


class CollaborationConfigStoreBase:
    def get_all(self) -> t.List[CollaborationConfigBase]:
        """
        Get all CollaborationConfigs, already resolved to the correct type
        """
        raise NotImplementedError

    def get(self, name: str):
        """Get a specific collab config by name"""
        return next((c for c in self.get_all() if c.name == name), None)
