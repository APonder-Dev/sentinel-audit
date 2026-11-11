"""Bounded JSON frames only; never deserialize executable objects."""

import json
import struct

MAX_FRAME = 16 * 1024 * 1024


def send_message(connection, message):
    payload = json.dumps(message, allow_nan=False).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("Worker message too large")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def receive_message(connection):
    def read_exact(size):
        chunks = bytearray()
        while len(chunks) < size:
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                raise EOFError("Worker connection closed")
            chunks.extend(chunk)
        return bytes(chunks)

    length = struct.unpack("!I", read_exact(4))[0]
    if not 0 < length <= MAX_FRAME:
        raise ValueError("Invalid worker message length")
    result = json.loads(read_exact(length))
    if not isinstance(result, dict):
        raise TypeError("Worker message must be an object")
    return result


def validate_rules(value):
    if not isinstance(value, dict) or len(value) > 65535:
        raise ValueError("Invalid port rules")
    rules = {}
    for key, entry in value.items():
        port = int(key)
        if not 1 <= port <= 65535 or not isinstance(entry, list) or len(entry) != 3:
            raise ValueError("Invalid port rule")
        if not all(isinstance(part, str) and len(part) <= 8192 for part in entry):
            raise ValueError("Invalid port rule values")
        if entry[0] not in {"high", "medium", "low", "informational"}:
            raise ValueError("Invalid severity")
        rules[port] = tuple(entry)
    return rules
