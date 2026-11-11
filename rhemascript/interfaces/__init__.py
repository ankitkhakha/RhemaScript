"""Runtime interface adapters with common validation and policy enforcement."""
from .runtime import InterfaceGateway, InterfaceError, InterfaceResponse
__all__ = ["InterfaceGateway", "InterfaceError", "InterfaceResponse"]
