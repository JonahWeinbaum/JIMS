def format_hex_ascii(data: bytes) -> str:
    """Format bytes as hex and printable ASCII."""
    hex_str = data.hex()
    ascii_str = "".join(
        c if 32 <= ord(c) <= 126 else "." for c in data.decode("ascii", errors="ignore")
    )
    return f"{hex_str} ({ascii_str})"
