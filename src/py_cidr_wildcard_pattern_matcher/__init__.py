"""Package init exporting the public matcher API."""

from .core import (
    WildcardPatternMatcher,
    parse_pattern,
    match_address,
)

__all__ = [
    "WildcardPatternMatcher",
    "parse_pattern",
    "match_address",
]
