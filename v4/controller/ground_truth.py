"""Experiment-owned directional labels; never an input to the classifier."""
import json
from pathlib import Path


class GroundTruth:
    def __init__(self, manifest=None):
        self.path = Path(manifest) if manifest else None
        self.version = None
        self.rules = {}
        self.run_id = "unregistered"
        self.refresh()

    def refresh(self):
        if not self.path:
            return
        try:
            version = self.path.stat().st_mtime_ns
            contents = self.path.read_text() if version != self.version else None
        except FileNotFoundError:
            # Windows-mounted WSL paths can briefly disappear during replace.
            # Retain the previous complete manifest until the next refresh.
            return
        if version != self.version:
            data = json.loads(contents)
            self.rules = {(r["src_ip"], r["dst_ip"], r["protocol"]): r["ground_truth"]
                          for r in data.get("flows", [])}
            self.run_id, self.version = data["run_id"], version

    def lookup(self, src, dst, protocol):
        return self.rules.get((src, dst, protocol), "unknown"), self.run_id
