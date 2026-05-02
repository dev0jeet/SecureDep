"""
watcher.py — File watcher for SecureDep v2
Watches requirements.txt / package.json for changes and triggers auto-scan.
"""

import threading
import time
from pathlib import Path
from typing import Callable

WATCH_FILES = {"requirements.txt", "package.json", "Pipfile", "pyproject.toml"}


class FileWatcher:
    """
    Polls watched dep files every 3 seconds.
    On change → calls on_change(path).
    Uses polling (not inotify) so it works cross-platform without extra deps.
    """

    def __init__(self, path: str, on_change: Callable[[str], None]):
        self.path      = path
        self.on_change = on_change
        self.running   = False
        self._thread   = None
        self._mtimes: dict[str, float] = {}

    def start(self):
        self.running = True
        self._snapshot()  # baseline
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _snapshot(self):
        for fpath in Path(self.path).rglob("*"):
            if fpath.name in WATCH_FILES:
                try:
                    self._mtimes[str(fpath)] = fpath.stat().st_mtime
                except OSError:
                    pass

    def _loop(self):
        while self.running:
            time.sleep(3)
            changed = False
            for fpath in Path(self.path).rglob("*"):
                if fpath.name in WATCH_FILES:
                    key = str(fpath)
                    try:
                        mtime = fpath.stat().st_mtime
                        if self._mtimes.get(key) != mtime:
                            self._mtimes[key] = mtime
                            changed = True
                    except OSError:
                        pass
            if changed:
                print(f"[Watcher] dep file changed → auto-scan {self.path}")
                try:
                    self.on_change(self.path)
                except Exception as e:
                    print(f"[Watcher] auto-scan error: {e}")
