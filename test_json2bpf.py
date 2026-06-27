#!/usr/bin/env python3
"""Round-trip and format tests for json2bpf.

Verifies that JSON configs survive encode → decode with name, type, and
config content preserved exactly.
"""

import io
import json
import struct
import unittest

import json2bpf


def decode_bpf(data: bytes) -> tuple[str, int, str]:
    """Decode a .bpf payload back into (name, profile_type, config_str)."""
    assert data[0] == json2bpf.MESSAGE_TYPE_PROFILE_CONTENT, "bad message type"
    assert data[1] == json2bpf.VERSION, "bad version"

    import gzip
    payload = gzip.decompress(bytes(data[2:]))
    reader = io.BytesIO(payload)

    name_len = json2bpf.read_uvarint(reader)
    name = reader.read(name_len).decode("utf-8")

    profile_type = struct.unpack(">i", reader.read(4))[0]

    config_len = json2bpf.read_uvarint(reader)
    config_str = reader.read(config_len).decode("utf-8")

    return name, profile_type, config_str


class TestRoundTrip(unittest.TestCase):
    """Encode JSON → .bpf → decode, assert equality."""

    def test_basic_round_trip(self):
        config = {"outbounds": [{"type": "direct"}], "inbounds": []}
        config_bytes = json.dumps(config).encode("utf-8")
        name = "test-profile"

        payload = json2bpf.convert_bytes(name, config_bytes)
        decoded_name, decoded_type, decoded_config = decode_bpf(payload)

        self.assertEqual(decoded_name, name)
        self.assertEqual(decoded_type, json2bpf.PROFILE_TYPE_LOCAL)
        # Config is re-serialized to pretty-printed JSON; compare parsed objects
        self.assertEqual(json.loads(decoded_config), config)

    def test_unicode_name(self):
        config = {"log": {"level": "info"}}
        payload = json2bpf.convert_bytes("东京服务器", json.dumps(config).encode())
        name, _, config_str = decode_bpf(payload)
        self.assertEqual(name, "东京服务器")
        self.assertEqual(json.loads(config_str), config)

    def test_empty_config(self):
        payload = json2bpf.convert_bytes("empty", b"{}")
        name, ptype, config_str = decode_bpf(payload)
        self.assertEqual(name, "empty")
        self.assertEqual(ptype, json2bpf.PROFILE_TYPE_LOCAL)
        self.assertEqual(json.loads(config_str), {})

    def test_config_pretty_printed(self):
        """Output config should be 2-space indented JSON."""
        payload = json2bpf.convert_bytes("p", b'{"a":1}')
        _, _, config_str = decode_bpf(payload)
        self.assertIn("  ", config_str)  # has indentation
        self.assertNotIn("\t", config_str)  # no tabs

    def test_no_bom_in_output(self):
        payload = json2bpf.convert_bytes("n", b'{"x":1}')
        self.assertNotIn(b"\xef\xbb\xbf", payload)

    def test_header_bytes(self):
        payload = json2bpf.convert_bytes("h", b"{}")
        self.assertEqual(payload[0], json2bpf.MESSAGE_TYPE_PROFILE_CONTENT)
        self.assertEqual(payload[1], json2bpf.VERSION)

    def test_deterministic_output(self):
        """Same input → identical bytes (mtime=0, no randomness)."""
        config = b'{"v": [1, 2, 3]}'
        a = json2bpf.convert_bytes("d", config)
        b = json2bpf.convert_bytes("d", config)
        self.assertEqual(a, b)


class TestUvarint(unittest.TestCase):
    def test_round_trip_values(self):
        for val in [0, 1, 127, 128, 255, 16384, 2**32, 2**63]:
            buf = io.BytesIO()
            json2bpf.write_uvarint(buf, val)
            reader = io.BytesIO(buf.getvalue())
            self.assertEqual(json2bpf.read_uvarint(reader), val)

    def test_eof_raises(self):
        reader = io.BytesIO(b"")
        with self.assertRaises(ValueError):
            json2bpf.read_uvarint(reader)


class TestConvertBytesErrors(unittest.TestCase):
    def test_invalid_json_raises_value_error(self):
        with self.assertRaises(ValueError):
            json2bpf.convert_bytes("bad", b"{not json")


if __name__ == "__main__":
    unittest.main()
