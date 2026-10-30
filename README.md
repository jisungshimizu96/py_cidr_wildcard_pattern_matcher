# py_cidr_wildcard_pattern_matcher

Matches IPv4 addresses against glob-style wildcard patterns such as `192.168.*.*`, as found in legacy firewall and access-control configurations.

## Usage

```python
from py_cidr_wildcard_pattern_matcher import WildcardPatternMatcher, parse_pattern, match_address

# One-off check
assert match_address("192.168.*.*", "192.168.0.10") is True

# Reusable compiled matcher (preferred for repeated lookups)
m = parse_pattern("10.0.0.*")
assert m.matches("10.0.0.1") is True
assert m.matches("10.0.1.1") is False
assert m.pattern == "10.0.0.*"
```

Exported names:

- `WildcardPatternMatcher(pattern)` — compile once, match many via `.matches(address)` and `.pattern`.
- `parse_pattern(pattern)` — convenience constructor returning a `WildcardPatternMatcher`.
- `match_address(pattern, address)` — compile-and-match in one call, for one-off use.

## Why this exists

Some older access-control formats predate CIDR and express "this /24" as `192.168.1.*` rather than `192.168.1.0/24`. This library gives that syntax a precise, dependency-free implementation for tooling that still has to read those rules.

The deliberate trade-off: the `*` here is a **glob on whole octet positions**, not a CIDR prefix mask. `10.0.*.*` matches `10.0.0.0` through `10.0.255.255`, which happens to coincide with `10.0.0.0/16`. But `10.0.0.0/23` (which cuts mid-octet) has **no** wildcard representation, and the library does not pretend otherwise. If you need real prefix matching, use CIDR directly — do not try to express it in globs.

## Awkward edges

- A wildcard must occupy a **whole** segment. `10.0.0.1*` and `10.0.0.*1` are parse errors, not partial wildcards. If you need substring matching within an octet, this is the wrong library.
- Octets with leading zeros (`10.0.0.01`) are rejected, for the same reason many modern parsers reject them: `010` is ambiguous across systems. Use bare decimal.
- Invalid addresses raise rather than silently returning `False`; an access-control primitive that accepts malformed input is a liability.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

