#!/usr/bin/env python3
"""
sing-box Profile Converter (JSON -> BPF)

This script converts standard sing-box JSON configuration files into the
Binary Profile Format (.bpf) used by sing-box clients.

Usage:
  1. Single file conversion:
     python3 json2bpf.py config.json

  2. Multiple files conversion:
     python3 json2bpf.py server1.json server2.json

  3. Help menu:
     python3 json2bpf.py -h

Output:
  The generated .bpf file(s) will ALWAYS be saved in the directory where
  this script is located.

Target: Python 3.10+
"""

import argparse
import gzip
import io
import struct
from pathlib import Path
from typing import cast

# ================= Protocol Constants =================
# MessageTypeProfileContent: Value 3 is required.
MESSAGE_TYPE_PROFILE_CONTENT: int = 3

# Protocol Version
VERSION: int = 1

# Profile Type: 0 = Local
PROFILE_TYPE_LOCAL: int = 0
# ======================================================


def write_uvarint(buffer: io.BytesIO | gzip.GzipFile, value: int) -> None:
    """
    Writes an unsigned integer as a Varint (Variable-length integer).
    """
    while value >= 0x80:
        _ = buffer.write(struct.pack("B", (value & 0xFF) | 0x80))
        value >>= 7
    _ = buffer.write(struct.pack("B", value))


def write_string(
    writer: io.BytesIO | gzip.GzipFile, content: str | bytes | None
) -> None:
    """
    Writes a string (or bytes) prefixed by its length (Varint).
    """
    if content is None:
        content = b""

    if isinstance(content, str):
        data = content.encode("utf-8")
    else:
        data = content

    write_uvarint(writer, len(data))
    _ = writer.write(data)


def create_payload(profile_name: str, config_content: bytes) -> bytes:
    """
    Generates the Gzip-compressed body of the BPF file.
    """
    buffer = io.BytesIO()

    # mtime=0 ensures deterministic binary output
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as writer:
        # Field 1: Name
        write_string(writer, profile_name)

        # Field 2: Type (Local = 0)
        # Expects Big-Endian Int32.
        _ = writer.write(struct.pack(">i", PROFILE_TYPE_LOCAL))

        # Field 3: Config Content
        write_string(writer, config_content)

    return buffer.getvalue()


def convert_file(input_path: Path) -> None:
    """
    Reads the JSON input and writes the BPF output to the script's directory.
    """
    if not input_path.exists():
        print(f"❌ Error: Input file not found: {input_path}")
        return

    # Determine the directory where this script is located
    script_dir = Path(__file__).parent.resolve()

    # Construct output path: Script Directory + Filename.bpf
    output_path = script_dir / f"{input_path.stem}.bpf"
    profile_name = input_path.stem

    print(f"⚙️  Processing: {input_path.name}")
    print(f"   ├── Profile Name: {profile_name}")

    try:
        # Read the raw JSON content as binary
        with input_path.open("rb") as f:
            config_content = f.read()
    except Exception as e:
        print(f"❌ Error reading input file: {e}")
        return

    # Generate the binary payload
    try:
        payload = create_payload(profile_name, config_content)
    except Exception as e:
        print(f"❌ Error generating payload: {e}")
        return

    # Write the final binary file
    try:
        with output_path.open("wb") as f:
            # Header Byte 1: Message Type
            _ = f.write(struct.pack("B", MESSAGE_TYPE_PROFILE_CONTENT))
            # Header Byte 2: Version
            _ = f.write(struct.pack("B", VERSION))
            # Body: Gzip Payload
            _ = f.write(payload)

        print(f"✅ Success! Saved to: {output_path}")
        print(
            f"   └── Size: {len(config_content)}B (raw) -> {output_path.stat().st_size}B (bpf)"
        )

    except Exception as e:
        print(f"❌ Error writing output file: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Sing-box JSON configuration to Binary Profile Format (.bpf)."
    )

    # Explicitly assign to _ to suppress unused return value warning
    _ = parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="One or more .json configuration files to convert.",
    )

    args = parser.parse_args()

    # Explicit cast to eliminate reportAny warning in strict mode
    input_files = cast(list[Path], args.files)

    print("🚀 Starting Sing-box Profile Converter...")
    print("------------------------------------------")

    for file_path in input_files:
        convert_file(file_path)
        print("------------------------------------------")


if __name__ == "__main__":
    main()
