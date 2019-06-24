"""Network facilitator - allows discovering devices in multi-interface settings."""
import logging

from .discover import get_networks, get_interfaces, get_broadcasts

__version__ = "0.0.7"

__all__ = ("__version__", "get_networks", "get_interfaces", "get_broadcasts")
