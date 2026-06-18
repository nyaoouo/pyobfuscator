"""Python-layer kernel protection: launcher/body packer + detection plugin framework.

Public entry: `pack_module`. Extension surface: subclass `Detector` and `@register` it to add a
detection signal that folds into the launcher's key selector (see `detectors.py`).
"""
from .core import pack_module
from .detectors import Detector, register, DETECTORS, build_detection

__all__ = ["pack_module", "Detector", "register", "DETECTORS", "build_detection"]
