"""Executable, fail-closed capability contract layer. Domain decisions remain evidence-led."""
from .runtime import CapabilityEngine, CapabilityError, CapabilityResult
__all__ = ["CapabilityEngine", "CapabilityError", "CapabilityResult"]
