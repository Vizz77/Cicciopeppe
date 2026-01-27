#!/usr/bin/env python3
# By https://github.com/srdnlen/exploitfarm

# Generated with <3 by gpt
# infos taken from https://github.com/enowars/EnoEngine?tab=readme-ov-file#flagsubmission-endpoint

import socket
from exploitfarm.models.enums import FlagStatus

# Map FlagStatus to substrings to look for in the lowercase response
RESPONSES = {
    FlagStatus.ok: ["valid"],
    FlagStatus.invalid: ["invalid", "ownflag", "illegal"],
    FlagStatus.wait: ["resubmit", "error", "spam"],
    FlagStatus.timeout: ["old"],
}


def submit(
    flags,
    ip: str = "10.0.13.37",
    port: int = 1337,
    tcp_timeout: int = 30,
):
    """
    Send one or more flags over a TCP socket to ip:port.
    Each flag is sent on its own line. The server will reply
    one line per flag. Yields tuples of (flag, status, raw_response).
    """
    # Prepare the newline‑delimited payload, ending with a final newline
    payload = "\n".join(flags) + "\n"

    # Open a TCP connection
    with socket.create_connection((ip, port), timeout=tcp_timeout) as sock:
        sock.sendall(payload.encode())
        sock.shutdown(socket.SHUT_WR)

        # Read until we get at least as many lines as flags, or the socket closes
        buffer = ""
        responses = []
        while len(responses) < len(flags):
            chunk = sock.recv(4096).decode(errors="ignore")
            if not chunk:
                break
            buffer += chunk
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                responses.append(line.strip())

    # If we got fewer responses than flags, pad with an unknown‑error placeholder
    while len(responses) < len(flags):
        responses.append("ERROR: No response received")

    # Parse each line into (flag, FlagStatus, raw_message)
    for flag, raw in zip(flags, responses):
        # Expect format "PREFIX: message"
        parts = raw.split(":", 1)
        prefix = parts[0].strip()
        message = parts[1].strip() if len(parts) > 1 else ""

        # Default to wait for any unrecognized response
        found_status = FlagStatus.wait

        # Directly map the OK case
        if prefix.upper() == "VALID":
            found_status = FlagStatus.ok
        else:
            # Check our RESPONSES substrings
            low = raw.lower()
            for status, subs in RESPONSES.items():
                if any(sub in low for sub in subs):
                    found_status = status
                    break

        yield (flag, found_status, raw)
