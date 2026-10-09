from __future__ import annotations

import socket
import ssl
from urllib.parse import unquote, urlsplit


def _resp_command(*parts: str) -> bytes:
    encoded = [part.encode("utf-8") for part in parts]
    return b"*" + str(len(encoded)).encode() + b"\r\n" + b"".join(
        b"$" + str(len(item)).encode() + b"\r\n" + item + b"\r\n"
        for item in encoded
    )


def _read_line(sock: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Redis closed the connection unexpectedly.")
        data.extend(chunk)
        if len(data) > 65536:
            raise ValueError("Redis response line exceeded the limit.")
    return bytes(data[:-2])


def _read_resp(sock: socket.socket):
    prefix = sock.recv(1)
    if not prefix:
        raise ConnectionError("Redis returned an empty response.")
    if prefix == b"+":
        return _read_line(sock).decode("utf-8")
    if prefix == b"-":
        raise ConnectionError("Redis command failed: " + _read_line(sock).decode("utf-8", "replace"))
    if prefix == b":":
        return int(_read_line(sock))
    if prefix == b"$":
        length = int(_read_line(sock))
        if length < 0:
            return None
        if length > 1024 * 1024:
            raise ValueError("Redis bulk response exceeded the limit.")
        chunks = bytearray()
        while len(chunks) < length + 2:
            chunk = sock.recv(length + 2 - len(chunks))
            if not chunk:
                raise ConnectionError("Redis returned a truncated bulk response.")
            chunks.extend(chunk)
        if not chunks.endswith(b"\r\n"):
            raise ValueError("Malformed Redis bulk response.")
        return bytes(chunks[:-2])
    if prefix == b"*":
        count = int(_read_line(sock))
        if count < 0:
            return None
        if count > 16:
            raise ValueError("Redis array response exceeded the limit.")
        return [_read_resp(sock) for _ in range(count)]
    raise ValueError("Unsupported Redis response type.")


def enforce_redis_rate_limit(redis_url: str, key: str, limit: int, window_seconds: int = 60) -> int | None:
    """Atomically enforce a fixed-window limit in Redis.

    Returns None when allowed, otherwise a positive Retry-After value. A
    configured Redis backend fails closed: connection/protocol errors propagate
    to the caller rather than silently falling back to a process-local counter.
    """
    parsed = urlsplit(redis_url)
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
        raise ValueError("Redis rate-limit URL must use redis:// or rediss://.")
    if parsed.query or parsed.fragment:
        raise ValueError("Redis rate-limit URL must not contain query or fragment.")
    try:
        port = parsed.port or 6379
    except ValueError as error:
        raise ValueError("Redis rate-limit URL has an invalid port.") from error
    database = parsed.path.lstrip("/") or "0"
    if not database.isdigit():
        raise ValueError("Redis rate-limit URL database must be a non-negative integer.")
    password = unquote(parsed.password or "")
    username = unquote(parsed.username or "")
    script = (
        "local n=redis.call('INCR',KEYS[1]); "
        "if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[2]) end; "
        "local ttl=redis.call('PTTL',KEYS[1]); "
        "if n>tonumber(ARGV[1]) then return {0,math.max(1,math.ceil(ttl/1000))} "
        "else return {1,0} end"
    )
    timeout = 2.0
    with socket.create_connection((parsed.hostname, port), timeout=timeout) as raw_sock:
        sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=parsed.hostname) if parsed.scheme == "rediss" else raw_sock
        with sock:
            sock.settimeout(timeout)
            if password:
                auth_parts = ("AUTH", username, password) if username else ("AUTH", password)
                sock.sendall(_resp_command(*auth_parts))
                _read_resp(sock)
            if database != "0":
                sock.sendall(_resp_command("SELECT", database))
                _read_resp(sock)
            sock.sendall(_resp_command("EVAL", script, "1", key, str(limit), str(window_seconds * 1000)))
            result = _read_resp(sock)
    if not isinstance(result, list) or len(result) != 2:
        raise ValueError("Redis returned an invalid rate-limit result.")
    return None if int(result[0]) == 1 else max(1, int(result[1]))
