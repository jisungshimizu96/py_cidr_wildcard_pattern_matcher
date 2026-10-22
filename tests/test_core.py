import unittest

from py_cidr_wildcard_pattern_matcher import (
    WildcardPatternMatcher,
    parse_pattern,
    match_address,
)


class ParsePatternTests(unittest.TestCase):
    def test_all_literals(self):
        m = parse_pattern("10.0.0.1")
        self.assertEqual(m.pattern, "10.0.0.1")

    def test_single_wildcard(self):
        parse_pattern("10.0.0.*")

    def test_multiple_wildcards(self):
        parse_pattern("192.168.*.*")

    def test_wrong_segment_count_rejected(self):
        with self.assertRaises(ValueError):
            parse_pattern("10.0.0")
        with self.assertRaises(ValueError):
            parse_pattern("10.0.0.1.2")

    def test_out_of_range_octet_rejected(self):
        with self.assertRaises(ValueError):
            parse_pattern("10.0.0.256")

    def test_non_digit_segment_rejected(self):
        with self.assertRaises(ValueError):
            parse_pattern("10.0.0.abc")

    def test_partial_wildcard_segment_rejected(self):
        with self.assertRaises(ValueError):
            parse_pattern("10.0.0.1*")
        with self.assertRaises(ValueError):
            parse_pattern("10.0.0.*1")

    def test_leading_zero_rejected(self):
        with self.assertRaises(ValueError):
            parse_pattern("10.0.0.01")

    def test_non_string_pattern_rejected(self):
        with self.assertRaises(TypeError):
            parse_pattern(123)  # type: ignore[arg-type]


class MatchesTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(match_address("10.0.0.1", "10.0.0.1"))

    def test_exact_mismatch(self):
        self.assertFalse(match_address("10.0.0.1", "10.0.0.2"))

    def test_wildcard_matches_any_value_in_position(self):
        self.assertTrue(match_address("10.0.0.*", "10.0.0.0"))
        self.assertTrue(match_address("10.0.0.*", "10.0.0.255"))

    def test_wildcard_does_not_match_other_prefixes(self):
        self.assertFalse(match_address("10.0.0.*", "10.0.1.0"))

    def test_multiple_wildcards(self):
        self.assertTrue(match_address("192.168.*.*", "192.168.0.1"))
        self.assertTrue(match_address("192.168.*.*", "192.168.255.255"))
        self.assertFalse(match_address("192.168.*.*", "192.169.0.1"))

    def test_all_wildcards_match_anything(self):
        self.assertTrue(match_address("*.*.*.*", "1.2.3.4"))

    def test_precompiled_matcher_reusable(self):
        m = WildcardPatternMatcher("172.16.*.5")
        self.assertTrue(m.matches("172.16.0.5"))
        self.assertTrue(m.matches("172.16.99.5"))
        self.assertFalse(m.matches("172.16.0.6"))
        self.assertFalse(m.matches("172.17.0.5"))


class AddressValidationTests(unittest.TestCase):
    def test_invalid_address_raises(self):
        m = WildcardPatternMatcher("10.0.0.*")
        with self.assertRaises(ValueError):
            m.matches("10.0.0")
        with self.assertRaises(ValueError):
            m.matches("10.0.0.256")
        with self.assertRaises(ValueError):
            m.matches("10.0.0.abc")
        with self.assertRaises(ValueError):
            m.matches("10.0.0.01")
        with self.assertRaises(ValueError):
            m.matches("10.0.0.1.2")

    def test_non_string_address_raises(self):
        m = WildcardPatternMatcher("10.0.0.*")
        with self.assertRaises(TypeError):
            m.matches(12345)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
