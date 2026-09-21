"""External tool bridges (nuclei / sqlmap / httpx) — see external.py."""

from .external import BRIDGES, BridgeResult, run_httpx_tech, run_nuclei, run_sqlmap

__all__ = ["BRIDGES", "BridgeResult", "run_nuclei", "run_sqlmap",
           "run_httpx_tech"]
