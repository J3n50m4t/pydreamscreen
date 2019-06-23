"""DreamScreen controller. Send commands to/from your DreamScreen via Wifi."""
import logging

from .devices import (
    DreamScreenHD,
    DreamScreen4K,
    DreamScreenSolo,
    SideKick,
    get_device,
    get_devices,
    get_states,
    get_state,
)

__version__ = "0.0.1"

__all__ = (
    "__version__",
    "get_device",
    "get_devices",
    "get_states",
    "get_state",
    "DreamScreenHD",
    "DreamScreen4K",
    "DreamScreenSolo",
    "SideKick",
)

_LOGGER = logging.getLogger(__name__)
