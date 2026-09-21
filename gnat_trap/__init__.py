"""GNTRP-X3M — behavioral defense module.

A session-scoped manipulation detector with escalating tiers:
green (reflect) -> yellow (warn) -> orange (countermeasure) -> red (lockout).
"""
from .engine import GnatTrapEngine
from .detector import scan, ScanResult, Detection
from .escalation import EscalationLadder, Tier
from .kintsugi import KintsugiLayer

__all__ = [
    "GnatTrapEngine",
    "scan",
    "ScanResult",
    "Detection",
    "EscalationLadder",
    "Tier",
    "KintsugiLayer",
]

__version__ = "0.2.0"
