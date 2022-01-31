#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

import collections
import datetime
import logging
from tabnanny import check
import time
from turtle import update
import typing as t
from threatexchange.cli.cli_config import CLISettings
from threatexchange.fetcher.collab_config import CollaborationConfigBase
from threatexchange.fetcher.fetch_api import SignalExchangeAPI
from threatexchange.fetcher.fetch_state import (
    FetchCheckpointBase,
    FetchedStateStoreBase,
)

from threatexchange.fetcher.meta_threatexchange import threat_updates
from threatexchange.fetcher.meta_threatexchange.api import ThreatExchangeAPI
from threatexchange.cli import command_base
from threatexchange.cli import dataset_cmd
from threatexchange.cli.cli_state import Dataset
from threatexchange.cli.dataset.simple_serialization import CliIndicatorSerialization


class FetchCommand(command_base.Command):
    """
    Download content from ThreatExchange to disk.

    Using the CollaborationConfig, download signals that
    correspond to a single collaboration, and store them in the state
    directory.

    This endpoint uses /threat_updates to fetch content sequentially, and in
    theory can be interrupted without issues.
    """

    PROGRESS_PRINT_INTERVAL_SEC = 30

    @classmethod
    def init_argparse(cls, ap) -> None:
        ap.add_argument(
            "--clean",
            action="store_true",
            help="force a refetch from the beginning of time (you almost never need to do this)",
        )
        ap.add_argument(
            "--skip-index-rebuild",
            action="store_true",
            help="don't rebuild indices after fetch",
        )
        ap.add_argument("--limit", type=int, help="stop after fetching this many items")
        ap.add_argument(
            "--per-collab-time-limit-sec",
            type=int,
            help="stop fetching after this many seconds",
        )
        ap.add_argument(
            "--only-api",
            help="only fetch from this API",
        )
        ap.add_argument(
            "--only-collab",
            help="only fetch for this collaboration",
        )

    def __init__(
        self,
        clean: bool,
        per_collab_time_limit_sec: t.Optional[int],
        limit: t.Optional[int],
        skip_index_rebuild: bool,
    ) -> None:
        self.clean = clean
        self.time_limit_sec = per_collab_time_limit_sec
        self.limit = limit
        self.skip_index_rebuild = skip_index_rebuild

        # Limits
        self.fetched_count = 0
        self.start_time = time.time()

        # Progress
        self.last_update_time = 0
        # Print first update after 5 seconds
        self.last_update_printed = time.time() - self.PROGRESS_PRINT_INTERVAL_SEC + 5
        self.processed = 0
        self.counts: t.Dict[str, int] = collections.Counter()

    def has_hit_limits(self):
        if self.limit is not None and self.fetched_count >= self.limit:
            return True
        if self.time_limit_sec is not None:
            if time.time() - self.start_time >= self.time_limit_sec:
                return True 
        return False

    def execute(self, settings: CLISettings) -> None:
        fetchers = settings.get_fetchers()

        all_succeeded = True
        any_succeded = False

        for fetcher in fetchers:
            succeeded = self.execute_for_fetcher(settings, fetcher)
            all_succeeded = all_succeeded and succeeded
            any_succeded = any_succeded or any_succeded

        if any_succeded and not self.skip_index_rebuild:
            self.stderr("Rebuilding match indices...")
            # TODO

        if not all_succeeded:
            raise command_base.CommandError("Some collabs had errors!", 3)

    def execute_for_fetcher(
        self, settings: CLISettings, fetcher: SignalExchangeAPI
    ) -> bool:
        success = True
        for collab in settings.get_collabs_for_fetcher(fetcher):
            try:
                self.execute_for_collab(settings, fetcher, collab)
            except Exception:
                msg = f"{collab.name} ({fetcher.get_name()}) failed to fetch!"
                self.stderr(msg)
                logging.exception(msg)
                success = False
        return success

    def execute_for_collab(
        self,
        settings: CLISettings,
        fetcher: SignalExchangeAPI,
        collab: CollaborationConfigBase,
    ) -> None:
        store: FetchedStateStoreBase = None

        checkpoint = self._verify_store_and_checkpoint(store, collab)

        if checkpoint is not None and checkpoint.is_up_to_date():
            return

        # TODO Print progress

        update_count = 0

        try:
            while not self.has_hit_limits(): 
                delta = fetcher.fetch_once(collab, checkpoint)
                update_count += delta.record_count()
                store.merge(collab, delta)
                checkpoint = delta.next_checkpoint
                assert checkpoint  # Infinite loop protection
                if not delta.has_more_data:
                    break 
        finally:
            store.flush()

    def _verify_store_and_checkpoint(
        self, store: FetchedStateStoreBase, collab: CollaborationConfigBase
    ) -> t.Optional[FetchCheckpointBase]:
        if self.clean:
            store.clear(collab)
            return None

        checkpoint = store.get_checkpoint(collab)

        if checkpoint.stale():
            store.clear(collab)
            return None

        return checkpoint

    def _progress(self, update: threat_updates.ThreatUpdateJSON) -> None:
        self.processed += 1
        self.counts[update.threat_type] += -1 if update.should_delete else 1
        self.last_update_time = update.time

        now = time.time()
        if now - self.last_update_printed >= self.PROGRESS_PRINT_INTERVAL_SEC:
            self.last_update_printed = now
            self._print_progress()

    def _print_progress(self):
        processed = ""
        if self.processed:
            processed = f"Downloaded {self.processed} updates. "

        on_privacy_group = ""
        if self.current_pgroup:
            on_privacy_group = f"on PrivacyGroup({self.current_pgroup}) "

        from_time = ""
        if not self.last_update_time:
            from_time = "ages long past"
        elif self.last_update_time >= time.time():
            from_time = "moments ago"
        else:
            delta = datetime.datetime.utcfromtimestamp(
                time.time()
            ) - datetime.datetime.utcfromtimestamp(self.last_update_time)
            parts = []
            for name, div in (
                ("year", datetime.timedelta(days=365)),
                ("day", datetime.timedelta(days=1)),
                ("hour", datetime.timedelta(hours=1)),
                ("minute", datetime.timedelta(minutes=1)),
                ("second", datetime.timedelta(seconds=1)),
            ):
                val, delta = divmod(delta, div)
                if val or parts:
                    parts.append((val, name))

            from_time = "now"
            if parts:
                str_parts = []
                for val, name in parts:
                    if str_parts:
                        str_parts.append(f"{val:02}{name[0]}")
                    else:
                        s = "s" if val > 1 else ""
                        str_parts.append(f"{val} {name}{s} ")
                from_time = f"{''.join(str_parts).strip()} ago"

        self.stderr(
            f"{processed}Currently {on_privacy_group}at {from_time}",
        )
