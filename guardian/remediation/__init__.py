"""Deterministic remediation candidates (the only fixes the Defense agent may propose) and applying verified ones."""
from .apply import apply_verified
from .candidates import build_candidates

__all__ = ["apply_verified", "build_candidates"]
