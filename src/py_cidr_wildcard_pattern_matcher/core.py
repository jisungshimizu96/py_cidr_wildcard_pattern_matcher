"""IPv4 wildcard pattern matching for legacy access-control semantics.

This module matches IPv4 dotted-quad addresses against glob-style
wildcard patterns such as ``192.168.*.*``. The motivation is legacy
firewall and access-control lists that historically used shell-style
globbing rather than CIDR notation. Supporting CIDR's proper prefix
masking here would conflate two different models of matching (glob on
digits vs. contiguous-bit-length masking), so this library keeps them
strictly separate: only ``*`` wildcards and literal octets are
recognised, and every non-octet or non-``*`` segment is a parse error.
"""

from __future__ import annotations

__all__ = [
    "WildcardPatternMatcher",
    "parse_pattern",
    "match_address",
]


def _parse_octet(token: str) -> int:
    """Parse a decimal octet token, rejecting leading zeros and out-of-range values.

    The IPv4 octet space is small (0..255). Historical ACL tooling in
    this library's target niche disallowed leading zeros to keep
    strings unambiguous (``010`` could otherwise be read as octal in
    other contexts). Enforcing the no-leading-zero rule explicitly
    here makes the pattern language deterministic.
    """
    if not token.isdigit():
        raise ValueError("octet must be all decimal digits: %r" % token)
    if len(token) > 1 and token.startswith("0"):
        raise ValueError("octet must not have a leading zero: %r" % token)
    value = int(token)
    if value < 0 or value > 255:
        raise ValueError("octet out of range [0, 255]: %r" % token)
    return value


def _parse_address(address: str) -> list:
    """Validate and normalise an IPv4 dotted-quad address into a list of ints."""
    if not isinstance(address, str):
        raise TypeError("address must be a string")
    parts = address.split(".")
    if len(parts) != 4:
        raise ValueError("address must have exactly four octets: %r" % address)
    return [_parse_octet(p) for p in parts]


class WildcardPatternMatcher:
    """Pre-compiled IPv4 wildcard pattern matcher.

    Compiling the pattern once at construction time keeps repeated
    matching against the same pattern cheap — the usual access-control
    workload (one ACL, many source IPs). Internally each octet of the
    pattern is either the sentinel ``None`` (meaning "match anything")
    or an ``int`` in ``[0, 255]``.
    """

    def __init__(self, pattern: str) -> None:
        if not isinstance(pattern, str):
            raise TypeError("pattern must be a string")
        parts = pattern.split(".")
        if len(parts) != 4:
            raise ValueError(
                "pattern must have exactly four segments: %r" % (pattern,)
            )
        compiled: list = []
        for part in parts:
            if part == "*":
                compiled.append(None)
            else:
                compiled.append(_parse_octet(part))
        # tuple is immutable and documentably small; safer than list for sharing
        self._compiled = tuple(compiled)
        self._pattern = pattern

    @property
    def pattern(self) -> str:
        """The exact pattern string this matcher was constructed from."""
        return self._pattern

    def matches(self, address: str) -> bool:
        """Return ``True`` if ``address`` matches this pattern.

        ``address`` must be a valid IPv4 dotted-quad; an invalid address
        raises rather than returning ``False``, because silently
        accepting malformed input in an access-control primitive is the
        kind of ambiguity that turns into a security incident.
        """
        octets = _parse_address(address)
        for want, got in zip(self._compiled, octets):
            if want is not None and want != got:
                return False
        return True


def parse_pattern(pattern: str) -> WildcardPatternMatcher:
    """Convenience: compile a pattern string into a ``WildcardPatternMatcher``."""
    return WildcardPatternMatcher(pattern)


def match_address(pattern: str, address: str) -> bool:
    """Convenience: compile ``pattern`` then test ``address`` in one step.

    Suitable for one-off checks. For repeated matching, keep the
    ``WildcardPatternMatcher`` object returned by ``parse_pattern``
    instead of re-parsing on every call.
    """
    return WildcardPatternMatcher(pattern).matches(address)
