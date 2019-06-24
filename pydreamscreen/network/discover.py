"""Used to discover Dreamscreen devices on the network"""
import logging
import netifaces  # type: ignore

_LOGGER = logging.getLogger(__name__)


def get_interfaces(excluded=None):
    """gets interfaces"""
    return [iface for iface in netifaces.interfaces() if iface not in excluded]


def get_networks(excluded=None):
    """gets networks"""
    return [
        netifaces.ifaddresses(iface)[netifaces.AF_INET]
        for iface in get_interfaces(excluded)
        if netifaces.AF_INET in netifaces.ifaddresses(iface)
    ]


def get_broadcasts(excluded=None):
    """gets broadcasts"""
    return [
        addr["broadcast"]
        for addresses in get_networks(excluded)
        for addr in addresses
        if "broadcast" in addr.keys()
    ]
