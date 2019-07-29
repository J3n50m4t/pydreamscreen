"""Gather state messages from DreamScreen devices."""
import datetime
import logging
import re
import socket
import sys

from typing import cast, Union, Dict, List, Generator, Optional

import crc8  # type: ignore

from .network import get_broadcasts

_LOGGER = logging.getLogger(__name__)

if "--debug" in sys.argv:
    logging.basicConfig(level=logging.DEBUG)

# pylint: disable=invalid-name,too-few-public-methods
# Gets rid of the annoying warnings
# Invalid attribute name "ip" (invalid-name)
# Too few public methods (0/2) (too-few-public-methods)


class _SendReadCurrentStateMessage:
    """Context manager to send a state message to the network."""

    READ_STATE_MESSAGE = b"\xFC\x05\xFF\x30\x01\x0A\x2A"

    def __init__(self, ip: str = "255.255.255.255") -> None:
        """Handle socket configuration."""
        self.ip = ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def __enter__(self):
        """Send message on initialization."""
        if self.ip == "255.255.255.255":
            for bcast in get_broadcasts():
                _LOGGER.debug("Sending to %s", bcast)
                self.socket.sendto(self.READ_STATE_MESSAGE, (bcast, 8888))
        else:
            self.socket.sendto(self.READ_STATE_MESSAGE, (self.ip, 8888))
        return self

    def __exit__(self, *args):
        """Close open socket."""
        self.socket.close()


class _ReceiveStateMessages:
    """Context manager to receive state messages from the network."""

    def __init__(self, timeout: float = 1.0) -> None:
        """Handle socket configuration."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(timeout)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def __enter__(self):
        """Send message on initialization."""
        self.socket.bind(("", 8888))
        return self

    def __exit__(self, *args):
        """Close open socket."""
        self.socket.close()

    def __iter__(self):
        """Iteration over network messages."""
        pattern = re.compile(b"\xfc[\x90-\xFF]\xff`\x01\n")
        try:
            _LOGGER.debug("Listening...")
            while True:
                message, address = self.socket.recvfrom(1024)
                ip, port = address
                _LOGGER.debug("Received message=%s from ip=%s port=[%s]", message, ip, port)
                if port == 8888 and pattern.match(message):
                    _LOGGER.debug("Processing state from ip=%s port=[%s]", ip, port)
                    parsed_message = self.parse_message(message[6:], ip)
                    if parsed_message:
                        _LOGGER.debug("Successfully parsed state message")
                        yield parsed_message
        except socket.timeout:
            return

    @staticmethod
    def parse_string(string: bytes) -> str:
        """Take bytes from packet into strimmed string."""
        try:
            return string.strip(b"\x00").decode("utf8").strip()
        except (ValueError, TypeError):
            _LOGGER.error(str(sys.exc_info()[1]))
        return ""

    @staticmethod
    def parse_message(
            message: bytes, ip: str
    ) -> Union[None, Dict[str, Union[str, int, bytes, datetime.datetime]]]:
        """Take a packet payload and convert to dictionary."""
        if message[-2] == 1:
            device_type = "DreamScreenHD"
        elif message[-2] == 2:
            device_type = "DreamScreen4K"
        elif message[-2] == 3:
            device_type = "SideKick"
        elif message[-2] == 7:
            device_type = "DreamScreenSolo"
        else:
            _LOGGER.debug("Unknown device type: %s", message[-2])
            return None
        parsed_message = {
            "ip": ip,
            "device_type": device_type,
            "update_time": datetime.datetime.now(),
            "recent_state_message": message,
        }  # type: Dict[str, Union[str, int, bytes, datetime.datetime]]

        parsed_message.update(
            {
                "name": _ReceiveStateMessages.parse_string(message[0:16]),
                "group_name": _ReceiveStateMessages.parse_string(message[16:32]),
                "group_number": message[32],
                "mode": message[33],
                "brightness": message[34],
                "ambient_color": message[40:43],
                "ambient_scene": message[62],
            }
        )
        _LOGGER.debug("Update: %s", parsed_message)
        if device_type != "SideKick":
            parsed_message.update(
                {
                    "hdmi_input": message[73],
                    "hdmi_input_1_name": _ReceiveStateMessages.parse_string(
                        message[75:91]
                    ),
                    "hdmi_input_2_name": _ReceiveStateMessages.parse_string(
                        message[91:107]
                    ),
                    "hdmi_input_3_name": _ReceiveStateMessages.parse_string(
                        message[107:123]
                    ),
                    "hdmi_active_channels": message[129],
                }
            )
        return parsed_message


class _BaseDreamScreenDevice:
    """Abstract base class for shared DreamScreen device methods."""

    # pylint: disable=too-many-instance-attributes

    def __init__(self, ip: str, **kwargs: Dict) -> None:
        """Device setup."""
        self._ip = ip  # type: str
        self._name = None  # type: Union[None, str]
        self._group_name = None  # type: Union[None, str]
        self._group_number = None  # type: Union[None, int]
        self._mode = None  # type: Union[None, int]
        self._brightness = None  # type: Union[None, int]
        self._ambient_color = None  # type: Union[None, bytes]
        self._ambient_scene = None  # type: Union[None, int]
        self._update_time = None  # type: Union[None, datetime.datetime]
        self._recent_state_message = None  # type: Union[None, bytes]

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # This is used for broadcasting to Groups vs. single devices
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        _LOGGER.debug("%s initialized", type(self).__name__)
        if "state" in kwargs and isinstance(kwargs["state"], dict):
            _LOGGER.debug("setting %s state", self.ip)
            self._update_current_state(kwargs["state"])

    def __str__(self):
        """Pretty format of device."""
        return "{}(ip={!r}, name={!r})".format(type(self).__name__, self.ip, self.name)

    def __repr__(self):
        """Representation of device initialiation."""
        return "{}(ip={!r})".format(type(self).__name__, self.ip)

    def update_current_state(self, timeout: float = 1.0) -> bool:
        """Force device to get current state."""
        current_state = get_state(self.ip, timeout)
        if current_state:
            self._update_current_state(current_state)
            return True
        _LOGGER.error("couldn't update state for device %s", self.ip)
        return False

    def _update_current_state(self, state: dict) -> bool:
        if "device_type" not in state:
            return False
        if state["device_type"] != type(self).__name__:
            _LOGGER.error(
                "device type mismatch %s != %s",
                type(self).__name__,
                state["device_type"],
            )
            return False
        for key, value in state.items():
            if key in self._mutable_properties:
                _LOGGER.debug("setting _%s to %s", key, value)
                setattr(self, "_{}".format(key), value)
        return True

    def _build_packet(
            self, namespace: int, command: int, payload: Union[List, tuple]
    ) -> bytearray:
        if not isinstance(payload, (list, tuple)):
            _LOGGER.error("payload type %s != list|tuple", type(payload))
        flags = 17 if self.group_number == 0 else 33
        resp = [252, len(payload) + 5, self.group_number, flags, namespace, command]
        resp.extend(payload)
        resp.extend(self._crc8(bytearray(resp)))
        return bytearray(resp)

    def _send_packet(
            self, data: bytearray, broadcast: bool = False, update: bool = True
    ) -> bool:
        if not isinstance(data, bytearray):
            _LOGGER.error("packet type %s != bytearray", type(data))
            return False
        _LOGGER.debug("sent %s", data)
        if broadcast:
            self.socket.sendto(data, ("255.255.255.255", 8888))
        else:
            self.socket.sendto(data, (self.ip, 8888))
        if update:
            self.update_current_state()
        return True

    @staticmethod
    def _crc8(data: bytearray) -> bytes:
        message_hash = crc8.crc8()
        message_hash.update(data)
        return message_hash.digest()

    @property
    def device_type(self) -> str:
        """Return Classname as Device Type."""
        return type(self).__name__

    @property
    def ip(self) -> str:
        """IP Address."""
        return self._ip

    @property
    def update_time(self) -> Optional[datetime.datetime]:
        """Time the state was updated."""
        return self._update_time

    @property
    def recent_state_message(self) -> Optional[bytes]:
        """Recent State Packet Received."""
        return self._recent_state_message

    @property
    def name(self) -> Optional[str]:
        """Device Name."""
        if self._name is None:
            success = self.update_current_state()
            if not success and not self._name:
                return "Unknown"
        return self._name

    @property
    def group_name(self) -> Optional[str]:
        """Group Name."""
        if self._group_name is None:
            success = self.update_current_state()
            if not success and not self._group_name:
                return "Unknown"
        return self._group_name

    @property
    def group_number(self) -> int:
        """Group Number."""
        if self._group_number is None:
            self.update_current_state()
        return cast(int, self._group_number)

    @property
    def mode(self) -> Optional[int]:
        """Selected DreamScreen Mode."""
        if self._mode is None:
            self.update_current_state()
        return self._mode

    @mode.setter
    def mode(self, value: int) -> None:
        """Set DreamScreen mode.

        0: Off
        1: Video
        2: Music
        3: Ambient
        """
        if not isinstance(value, int):
            raise TypeError("expected int got {}".format(type(value)))
        if 0 <= value <= 3:
            self._send_packet(
                self._build_packet(namespace=3, command=1, payload=[value])
            )
        else:
            raise ValueError("value {} out of bounds".format(value))

    @property
    def brightness(self) -> int:
        """LED Brightness."""
        if self._brightness is None:
            self.update_current_state()
        return cast(int, self._brightness)

    @brightness.setter
    def brightness(self, value: int) -> None:
        """Set LED brightness.

        Brightness values between 0 and 100
        """
        if not isinstance(value, int):
            raise TypeError("expected int got {}".format(type(value)))
        if 0 <= value <= 100:
            self._send_packet(
                self._build_packet(namespace=3, command=2, payload=[value])
            )
        else:
            raise ValueError("value {} out of bounds".format(value))

    @property
    def ambient_color(self) -> bytes:
        """Ambient Scene Color."""
        if self._ambient_color is None:
            self.update_current_state()
        return cast(bytes, self._ambient_color)

    @ambient_color.setter
    def ambient_color(self, value: Union[tuple, list, bytes, str]) -> None:
        r"""Set DreamScreen ambient color.

        Takes tuple/list of RGB
        e.g. (200,150,50) or [200, 150, 50]
        or hex value of color as string
        e.g. '#C89632' or '#c93' or u'#C89632'
        or bytes of color
        e.g. b'\xc8\x96\x32' or b'\xc8\x962'
        """
        new_color = []  # type: List[int]
        if isinstance(value, (tuple, list)):
            for color in value:
                if 0 <= color <= 255:
                    new_color.append(color)
        # Convert to bytes so next if statement takes care of it
        elif isinstance(value, str) and value[0] == "#":
            if len(value) == 4:
                value = bytes(
                    bytearray.fromhex(
                        "".join(a + b for a, b in zip(value[1:], value[1:]))
                    )
                )
            elif len(value) == 7:
                value = bytes(bytearray.fromhex(value[1:]))
        if isinstance(value, bytes):
            if len(value) == 3:
                for color in value:
                    if 0 <= color <= 255:
                        new_color.append(color)
        if len(new_color) == 3:
            self._send_packet(
                self._build_packet(namespace=3, command=8, payload=[0]), update=False
            )
            self._send_packet(
                self._build_packet(namespace=3, command=5, payload=new_color)
            )
        else:
            raise TypeError("incomprehensible value given {!r}".format(value))

    @property
    def ambient_scene(self) -> int:
        """Ambient Scene."""
        if self._ambient_scene is None:
            self.update_current_state()
        return cast(int, self._ambient_scene)

    @ambient_scene.setter
    def ambient_scene(self, value: int) -> None:
        """Set DreamScreen ambient scene.

        Scenes from the app:
        0: Random Colors
        1: Fireside
        2: Twinkle
        3: Ocean
        4: Pride
        5: July 4th
        6: Holiday
        7: Pop
        8: Enchanted Forrest
        """
        if not isinstance(value, int):
            raise TypeError("expected int got {}".format(type(value)))
        if 0 <= value <= 8:
            self._send_packet(
                self._build_packet(namespace=3, command=8, payload=[1]), update=False
            )
            self._send_packet(
                self._build_packet(namespace=3, command=13, payload=[value])
            )
        else:
            raise ValueError("value {} out of bounds".format(value))

    @property
    def _mutable_properties(self):
        """All available mutable properties.

        Each subclass can specify what state messages should/could be
        changeable.  This impacts what will be updated on state updates and
        what users are able to change through the setter properties.

        This needs to be implemented on each base device type individually.
        """
        raise NotImplementedError


class DreamScreen(_BaseDreamScreenDevice):
    """Abstract for shared DreamScreen HD & 4K Attributes."""

    def __init__(self, *args, **kwargs):
        """Initialize Base & Specific Attributes."""
        super(DreamScreen, self).__init__(*args, **kwargs)
        self._hdmi_input = None  # type: int
        self._hdmi_input_1_name = None  # type: str
        self._hdmi_input_2_name = None  # type: str
        self._hdmi_input_3_name = None  # type: str
        self._hdmi_active_channels = None  # type: int

    @property
    def _mutable_properties(self):
        """Return DreamScreen HD & 4K Mutable Properties."""
        return [
            "ip",
            "name",
            "update_time",
            "recent_state_message",
            "group_name",
            "group_number",
            "mode",
            "brightness",
            "ambient_color",
            "ambient_scene",
            "hdmi_input",
            "hdmi_input_1_name",
            "hdmi_input_2_name",
            "hdmi_input_3_name",
            "hdmi_active_channels",
        ]

    @property
    def hdmi_input(self) -> int:
        """hdmi_input."""
        if self._hdmi_input is None:
            self.update_current_state()
        return self._hdmi_input

    @hdmi_input.setter
    def hdmi_input(self, value: int) -> None:
        """Set DreamScreen HDMI input.

        0: HDMI Source 1
        1: HDMI Source 2
        2: HDMI Source 3
        """
        if not isinstance(value, int):
            raise TypeError("expected int got {}".format(type(value)))
        if 0 <= value <= 2:
            self._send_packet(
                self._build_packet(namespace=3, command=32, payload=[value])
            )
        else:
            raise ValueError("value {} out of bounds".format(value))

    @property
    def hdmi_input_1_name(self) -> str:
        """HDMI Input 1 Name."""
        if self._hdmi_input_1_name is None:
            self.update_current_state()
        return self._hdmi_input_1_name

    @property
    def hdmi_input_2_name(self) -> str:
        """HDMI Input 2 Name."""
        if self._hdmi_input_2_name is None:
            self.update_current_state()
        return self._hdmi_input_2_name

    @property
    def hdmi_input_3_name(self) -> str:
        """HDMI Input 3 Name."""
        if self._hdmi_input_3_name is None:
            self.update_current_state()
        return self._hdmi_input_3_name

    @property
    def hdmi_active_channels(self) -> int:
        """HDMI Active Channels."""
        if not self._hdmi_active_channels:
            self.update_current_state()
        return self._hdmi_active_channels


class DreamScreenHD(DreamScreen):
    """DreamScreenHD Class.

    This is mostly so the names appear correctly since they're identical
    in functionality (for now) but who knows if anything changes in the future.
    """


class DreamScreen4K(DreamScreen):
    """DreamScreen4K Class.

    This is mostly so the names appear correctly since they're identical
    in functionality (for now) but who knows if anything changes in the future.
    """

class DreamScreenSolo(DreamScreen):
    """DreamScreenSolo Class.

    This is mostly so the name appear correctly since they're identical
    in functionality (for now) but who knows if anything changes in the future.
    """


class SideKick(_BaseDreamScreenDevice):
    """SideKick Class."""

    @property
    def _mutable_properties(self):
        """Return SideKick Mutable Properties."""
        return [
            "ip",
            "name",
            "group_name",
            "group_number",
            "mode",
            "brightness",
            "ambient_color",
            "ambient_scene",
        ]

def get_device(
        state: Dict[str, Union[str, int, bytes, datetime.datetime]]
) -> Union[None, DreamScreenHD, DreamScreen4K, DreamScreenSolo, SideKick]:
    """Return device ip and"""
    if state["device_type"] == "DreamScreenHD":
        return DreamScreenHD(ip=state["ip"], state=state)
    if state["device_type"] == "DreamScreen4K":
        return DreamScreen4K(ip=state["ip"], state=state)
    if state["device_type"] == "DreamScreenSolo":
        return DreamScreenSolo(ip=state["ip"], state=state)
    if state["device_type"] == "SideKick":
        return SideKick(ip=cast(str, state["ip"]), state=state)

    return None


def get_devices(
        timeout: float = 1.0
) -> List[Union[DreamScreenHD, DreamScreen4K, DreamScreenSolo, SideKick]]:
    """Return all of the currently detected devices on the network."""
    devices = []  # type: List[Union[DreamScreenHD, DreamScreen4K, DreamScreenSolo , SideKick]]
    for state in get_states(timeout=timeout):
        _LOGGER.debug("Received state: %s", state)
        device = get_device(state)
        if device is not None:
            devices.append(
                cast(
                    Union[DreamScreenHD, DreamScreen4K, DreamScreenSolo, SideKick],
                    device
                    )
                )
    _LOGGER.debug("Devices: %s", devices)
    return devices


def get_states(ip: str = "255.255.255.255", timeout: float = 1.0) -> Generator:
    """State message generator for all devices found."""
    with _ReceiveStateMessages(timeout=timeout) as states, _SendReadCurrentStateMessage(
            ip=ip
    ):

        for state in states:
            yield state


def get_state(
        ip: str, timeout: float = 1.0
) -> Union[None, Dict[str, Union[str, int, bytes, datetime.datetime]]]:
    """State message generator for a specific device."""
    for state in get_states(ip=ip, timeout=timeout):
        if state["ip"] == ip:
            return state
    _LOGGER.error("couldn't get_state of %s", ip)
    return None


def _main_messages():
    """Example of getting states."""
    import time

    class _Timer:
        start = None

        def __enter__(self):
            self.start = time.time()
            return self

        def __exit__(self, *args):
            print("Time taken: {:.6f}".format(time.time() - self.start))

    with _Timer():
        # Wait a set period of seconds, always. Might be useful for
        # initial/slow discovery of devices.
        for state in get_states(timeout=5):
            print(state)

    with _Timer():
        # Break after getting one good state.
        # Could also check if IP matches or can specify IP in state to ensure
        # only getting state message from required device.
        for state in get_states(timeout=5):
            print(state)
            # This could be a break after getting a specific
            # IP or certain name so it's not stuck waiting forever.
            break


def _main_devices():
    for device in get_devices():
        # print("{!r} Brightness -> {}".format(device, device.brightness))
        device.brightness = 100
        # print("{!r} Brightness -> {}".format(device, device.brightness))
        device.ambient_color = "#FFcc00"


if __name__ == "__main__":
    _main_messages()
    _main_devices()
