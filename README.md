# json2bpf

A Python tool that converts sing-box JSON configuration files into the
Binary Profile Format (`.bpf`) used by sing-box clients (SFA, SFM, NekoBox, etc.).

## Usage

```bash
# Convert a single file
python3 json2bpf.py config.json

# Convert multiple files
python3 json2bpf.py server1.json server2.json

# Set a custom profile name
python3 json2bpf.py -n "Tokyo Server" config.json

# Specify output path
python3 json2bpf.py -o /path/to/output.bpf config.json

# Read from stdin
cat config.json | python3 json2bpf.py -

# Inspect a .bpf file
python3 json2bpf.py --verify myprofile.bpf
```

## Binary Format

The `.bpf` format is defined in
[`experimental/libbox/profile_import.go`](https://github.com/SagerNet/sing-box/blob/main/experimental/libbox/profile_import.go)
in the sing-box source.

```
[0x03]                              MessageTypeProfileContent
[0x01]                              version (1)
[gzip compressed payload]:
    uvarint(len) + name_bytes       profile name (UTF-8)
    big-endian int32                profile type (0=Local, 1=iCloud, 2=Remote)
    uvarint(len) + config_bytes     JSON configuration (UTF-8)
    (conditional fields for Remote/iCloud profiles)
```

## Requirements

- Python 3.10+ (uses `X | Y` union types)
- No external dependencies (stdlib only)

## How it works

1. Reads and validates the input JSON configuration
2. Warns about common config issues (missing `outbounds`, unknown keys)
3. Re-serializes JSON to compact form (no whitespace, no BOM)
4. Encodes as a uvarint-length-prefixed binary payload
5. Wraps in a gzip stream matching Go's `compress/gzip` defaults
6. Prepends the 2-byte message header (`0x03 0x01`)
