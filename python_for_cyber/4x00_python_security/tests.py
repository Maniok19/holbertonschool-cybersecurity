#!/usr/bin/env python3
import unittest
from utils import validate_line, check_policy, hash_password, configure


class TestValidateLine(unittest.TestCase):
    def test_valid_email_pass(self):
        self.assertTrue(validate_line("user@example.com:secret123"))

    def test_invalid_format_no_colon(self):
        self.assertFalse(validate_line("user@example.com secret123"))

    def test_missing_parts(self):
        self.assertFalse(validate_line(":secret123"))
        self.assertFalse(validate_line("user@example.com:"))

    def test_invalid_email(self):
        self.assertFalse(validate_line("not-an-email:secret123"))


class TestCheckPolicy(unittest.TestCase):
    def setUp(self):
        # MinLength=8, no common-list hits unless we add them
        configure(salt="test-salt", min_length=8, common_list={"password"})

    def test_short_password(self):
        self.assertEqual(check_policy("abc1"), "WEAK")

    def test_numeric_only_password(self):
        self.assertEqual(check_policy("abcdefgh"), "WEAK")  # letters only, no digit

    def test_compliant_password(self):
        self.assertEqual(check_policy("Str0ngPass"), "COMPLIANT")

    def test_common_list_password(self):
        self.assertEqual(check_policy("password"), "WEAK")


class TestHashPassword(unittest.TestCase):
    def test_deterministic(self):
        h1 = hash_password("secret123", "salt")
        h2 = hash_password("secret123", "salt")
        self.assertEqual(h1, h2)

    def test_salt_changes_hash(self):
        self.assertNotEqual(
            hash_password("secret123", "salt-a"),
            hash_password("secret123", "salt-b"),
        )

    def test_known_length(self):
        self.assertEqual(len(hash_password("secret123", "salt")), 64)


if __name__ == "__main__":
    unittest.main()
