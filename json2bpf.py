#!/usr/bin/env python3
"""
sing-box Profile Converter (JSON -> BPF)

Converts sing-box JSON configuration files into the Binary Profile Format (.bpf)
used by sing-box clients (SFA, SFM, NekoBox, etc.).

Format reference: experimental/libbox/profile_import.go in SagerNet/sing-box

Wire format:
  [0x03]                              MessageTypeProfileContent
  [0x01]                              version
  [gzip compressed payload]:
      uvarint(len) + name_bytes       profile name
      big-endian int32                profile type (0=Local, 1=iCloud, 2=Remote)
      uvarint(len) + config_bytes     JSON config
      (conditional fields for Remote profiles)

Usage:
  python3 json2bpf.py config.json              # convert single file
  python3 json2bpf.py a.json b.json            # convert multiple files
  python3 json2bpf.py -n "My Server" config.json  # custom profile name
  python3 json2bpf.py --verify output.bpf      # inspect a .bpf file
  cat config.json | python3 json2bpf.py -      # read from stdin

Target: Python 3.10+
"""

import argparse
import gzip
import io
import json
import struct
import sys
import zlib
from pathlib import Path
from typing import BinaryIO, cast

# Default output directory: subfolder of the script's own directory
SCRIPT_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = SCRIPT_DIR / "output"

def _err(msg: str) -> None:
    """Print error to stderr, flushing stdout first to maintain output order."""
    sys.stdout.flush()
    print(msg, file=sys.stderr)


# ================= Protocol Constants =================
# From experimental/libbox/profile_import.go
MESSAGE_TYPE_ERROR = 0
MESSAGE_TYPE_PROFILE_LIST = 1
MESSAGE_TYPE_PROFILE_CONTENT_REQUEST = 2
MESSAGE_TYPE_PROFILE_CONTENT = 3

VERSION: int = 1

# Profile types (int32)
PROFILE_TYPE_LOCAL = 0
PROFILE_TYPE_ICLOUD = 1
PROFILE_TYPE_REMOTE = 2

# Gzip defaults matching Go's compress/gzip
_GZIP_COMPRESSION_LEVEL = zlib.Z_DEFAULT_COMPRESSION  # level 6 in CPython
_GZIP_MTIME = 0  # deterministic output
# ======================================================


def _write_gzip_header(buf: BinaryIO) -> None:
    """Write a gzip header matching Go's gzip.NewWriter defaults."""
    buf.write(b"\x1f\x8b")          # magic
    buf.write(b"\x08")              # method = DEFLATE
    buf.write(b"\x00")              # flags: FHCRC=0, FEXTRA=0, FNAME=0, FCOMMENT=0
    buf.write(struct.pack("<I", _GZIP_MTIME))  # mtime (little-endian uint32)
    buf.write(b"\x00")              # extra flags: XFL=0 (default, matches Go's gzip.NewWriter)
    buf.write(b"\xff")              # OS = 0xFF (unknown, same as Python's GzipFile)


def write_uvarint(buffer: BinaryIO, value: int) -> None:
    """Write an unsigned integer as a Protobuf-style Varint."""
    while value >= 0x80:
        buffer.write(struct.pack("B", (value & 0xFF) | 0x80))
        value >>= 7
    buffer.write(struct.pack("B", value & 0xFF))


def read_uvarint(reader: BinaryIO) -> int:
    """Read a Protobuf-style Varint from a binary stream."""
    result, shift = 0, 0
    while True:
        b = reader.read(1)
        if not b:
            raise ValueError("Unexpected EOF in uvarint")
        byte = b[0]
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result
        shift += 7


def write_string(buffer: BinaryIO, content: str) -> None:
    """Write a uvarint-length-prefixed UTF-8 string."""
    data = content.encode("utf-8")
    write_uvarint(buffer, len(data))
    buffer.write(data)


def create_payload(name: str, config: str) -> bytes:
    """
    Create the complete .bpf binary payload.

    Mirrors ProfileContent.Encode() from profile_import.go:
    1. Header: message type + version
    2. Gzip body: name + type + config (+ conditional fields)
    """
    buf = io.BytesIO()

    # --- Header (before gzip) ---
    buf.write(struct.pack("B", MESSAGE_TYPE_PROFILE_CONTENT))
    buf.write(struct.pack("B", VERSION))

    # --- Gzip-compressed body ---
    # We use a raw deflate compressor to build the gzip stream manually,
    # matching Go's flush order: write all data → flush deflate → write gzip trailer.
    _write_gzip_header(buf)

    compressor = zlib.compressobj(_GZIP_COMPRESSION_LEVEL, zlib.DEFLATED,
                                  -zlib.MAX_WBITS)

    # Inner payload (mirrors Go's bufio.NewWriter → gzip.NewWriter chain)
    inner = io.BytesIO()

    # Field 1: Name
    write_string(inner, name)

    # Field 2: Type (Local = 0, big-endian int32)
    inner.write(struct.pack(">i", PROFILE_TYPE_LOCAL))

    # Field 3: Config content
    write_string(inner, config)

    # For Remote profiles (not used for Local, but format-aware):
    # if type != PROFILE_TYPE_LOCAL:
    #     write_string(inner, remote_path)
    # if type == PROFILE_TYPE_REMOTE:
    #     inner.write(struct.pack(">?", auto_update))
    #     inner.write(struct.pack(">i", auto_update_interval))
    #     inner.write(struct.pack(">q", last_updated))

    payload = inner.getvalue()

    # Deflate in one shot (matching Go's Flush behavior)
    compressed = compressor.compress(payload)
    compressed += compressor.flush(zlib.Z_FINISH)
    buf.write(compressed)

    # Gzip trailer: CRC32 + ISIZE (little-endian)
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    buf.write(struct.pack("<I", crc))
    buf.write(struct.pack("<I", len(payload) & 0xFFFFFFFF))

    return buf.getvalue()


def convert_bytes(name: str, config_bytes: bytes) -> bytes:
    """Convert raw JSON config bytes to .bpf binary format."""
    # Re-serialize JSON to ensure consistent encoding (compact, no BOM)
    config = json.loads(config_bytes)
    normalized = json.dumps(config, ensure_ascii=False, indent=2)
    return create_payload(name, normalized)


def convert_file(input_path: Path, output_path: Path | None, name: str | None) -> bool:
    """Convert a single JSON file to .bpf format."""
    if not input_path.exists():
        print(f"❌ File not found: {input_path}", file=sys.stderr)
        return False

    profile_name = name or input_path.stem

    try:
        config_bytes = input_path.read_bytes()
    except Exception as e:
        _err(f"⚙️  {input_path.name} → ❌ Read error: {e}")
        return False

    try:
        payload = convert_bytes(profile_name, config_bytes)
    except ValueError as e:
        _err(f"⚙️  {input_path.name} → ❌ {e}")
        return False

    # Determine output path
    if output_path is None:
        OUTPUT_DIR.mkdir(exist_ok=True)
        out = OUTPUT_DIR / f"{input_path.stem}.bpf"
    else:
        out = output_path

    try:
        out.write_bytes(payload)
    except Exception as e:
        _err(f"⚙️  {input_path.name} → ❌ Write error: {e}")
        return False

    raw_size = len(config_bytes)
    bpf_size = len(payload)
    print(f"⚙️  {input_path.name} → {out.name}  ({raw_size}B → {bpf_size}B)")
    return True


def convert_stdin(name: str, output_path: Path | None) -> bool:
    """Convert JSON from stdin to .bpf format."""
    try:
        config_bytes = sys.stdin.buffer.read()
    except Exception as e:
        _err(f"⚙️  stdin → ❌ Read error: {e}")
        return False

    try:
        payload = convert_bytes(name, config_bytes)
    except ValueError as e:
        _err(f"⚙️  stdin → ❌ {e}")
        return False

    # Sanitize: strip directory components, use stem (no extension), add .bpf
    safe_stem = Path(Path(name).name).stem
    if output_path is None:
        OUTPUT_DIR.mkdir(exist_ok=True)
        out = OUTPUT_DIR / f"{safe_stem}.bpf"
    else:
        out = output_path

    try:
        out.write_bytes(payload)
    except Exception as e:
        _err(f"⚙️  stdin → ❌ Write error: {e}")
        return False

    print(f"⚙️  stdin → {out.name}  ({len(config_bytes)}B → {len(payload)}B)")
    return True


def verify_file(path: Path) -> None:
    """Read and display the structure of a .bpf file."""
    if not path.exists():
        print(f"❌ File not found: {path}", file=sys.stderr)
        sys.exit(1)

    data = path.read_bytes()
    print(f"📄 {path.name}  ({len(data)} bytes)")
    print("   Hex dump (first 64 bytes):")
    for i in range(0, min(64, len(data)), 16):
        hex_part = " ".join(f"{b:02x}" for b in data[i:i + 16])
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i + 16])
        print(f"   {i:04x}  {hex_part:<48}  {ascii_part}")

    if len(data) < 2:
        print("   ❌ File too small to contain header", file=sys.stderr)
        return

    msg_type = data[0]
    version = data[1]
    type_names = {0: "Error", 1: "ProfileList", 2: "ContentRequest", 3: "ProfileContent"}
    print(f"\n   Message Type: {msg_type} ({type_names.get(msg_type, 'Unknown')})")
    print(f"   Version:      {version}")

    if msg_type != MESSAGE_TYPE_PROFILE_CONTENT:
        print("   ⚠️  Not a ProfileContent message")
        return

    if len(data) < 3:
        print("   ❌ No gzip payload", file=sys.stderr)
        return

    # Decompress gzip payload
    try:
        payload = gzip.decompress(bytes(data[2:]))
    except Exception as e:
        print(f"   ❌ Gzip decompression failed: {e}", file=sys.stderr)
        return

    print(f"   Gzip payload: {len(payload)} bytes (decompressed)")

    # Parse the payload
    reader = io.BytesIO(payload)

    try:
        # Name
        name_len = read_uvarint(reader)
        name_bytes = reader.read(name_len)
        if len(name_bytes) < name_len:
            print("   ❌ Truncated name field")
            return
        name = name_bytes.decode("utf-8")
        print(f"   Name:         \"{name}\"")

        # Type
        type_bytes = reader.read(4)
        if len(type_bytes) < 4:
            print("   ❌ Truncated type field")
            return
        profile_type = struct.unpack(">i", type_bytes)[0]
        type_labels = {0: "Local", 1: "iCloud", 2: "Remote"}
        print(f"   Type:         {profile_type} ({type_labels.get(profile_type, 'Unknown')})")

        # Config
        config_len = read_uvarint(reader)
        config_bytes = reader.read(config_len)
        if len(config_bytes) < config_len:
            print("   ❌ Truncated config field")
            return
        config_str = config_bytes.decode("utf-8")
        print(f"   Config:       {config_len} bytes")

        # Try to pretty-print a preview
        try:
            config = json.loads(config_str)
            keys = list(config.keys())
            print(f"   JSON keys:    {keys}")
            if "outbounds" in config:
                ob_count = len(config["outbounds"]) if isinstance(config["outbounds"], list) else "?"
                print(f"   Outbounds:    {ob_count}")
        except json.JSONDecodeError:
            print("   ⚠️  Config is not valid JSON")

    except Exception as e:
        print(f"   ❌ Parse error: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert sing-box JSON configs to Binary Profile Format (.bpf).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s config.json                     Convert a single file
  %(prog)s server1.json server2.json       Convert multiple files
  %(prog)s -n "Tokyo" config.json          Set custom profile name
  %(prog)s -o out.bpf config.json          Specify output path
  cat config.json | %(prog)s -             Read from stdin
  %(prog)s --verify myprofile.bpf          Inspect a .bpf file

Binary format (v1):
  [0x03][0x01][gzip: uvarint name | BE int32 type | uvarint config]
""",
    )

    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="JSON config file(s) to convert. Use '-' for stdin.",
    )
    parser.add_argument(
        "-n", "--name",
        help="Profile name (default: input filename without extension)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file path (only valid with single input)",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        metavar="FILE",
        help="Inspect and display the structure of a .bpf file",
    )

    args = parser.parse_args()

    # Verify mode
    if args.verify:
        verify_file(args.verify)
        return

    # Convert mode
    files = cast(list[Path], args.files)
    if not files:
        parser.error("No input files specified. Use --help for usage.")

    if args.output and len(files) > 1 and files[0] != Path("-"):
        parser.error("--output can only be used with a single input file.")

    print("🚀 sing-box Profile Converter")
    print("─" * 40)

    success = 0
    total = 0

    for fp in files:
        if fp == Path("-"):
            total += 1
            if convert_stdin(args.name or "stdin", args.output):
                success += 1
        else:
            total += 1
            if convert_file(fp, args.output if len(files) == 1 else None, args.name):
                success += 1

    print("─" * 40)
    print(f"✅ {success}/{total} file(s) converted successfully.")


if __name__ == "__main__":
    main()
