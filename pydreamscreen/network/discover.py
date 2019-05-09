import netifaces  # type: ignore
import logging

_LOGGER = logging.getLogger(__name__)


def get_interfaces(excluded=[]):
    return [iface for iface in netifaces.interfaces() if iface not in excluded]


def get_networks(excluded=[]):
    return [
        netifaces.ifaddresses(iface)[netifaces.AF_INET]
        for iface in get_interfaces(excluded)
        if netifaces.AF_INET in netifaces.ifaddresses(iface)
    ]


def get_broadcasts(excluded=[]):
    return [
        addr["broadcast"]
        for addresses in get_networks(excluded)
        for addr in addresses
        if "broadcast" in addr.keys()
    ]
