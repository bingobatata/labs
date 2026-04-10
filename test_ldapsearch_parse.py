"""Tests for ldapsearch_parse.py — covers parsing, base64, and entry boundary bugs."""

import base64
import io
from unittest.mock import patch

import pytest

from ldapsearch_parse import parse_ldap_users, _extract_value, main


# ── _extract_value ──────────────────────────────────────────────────────

class TestExtractValue:
    def test_plain_value(self):
        assert _extract_value("sAMAccountName: jdoe") == "jdoe"

    def test_base64_value(self):
        encoded = base64.b64encode("José".encode()).decode()
        assert _extract_value(f"displayName:: {encoded}") == "José"

    def test_base64_bad_padding_returns_raw(self):
        result = _extract_value("displayName:: !!!not-base64!!!")
        assert isinstance(result, str)

    def test_value_with_colon_in_it(self):
        # e.g. description: OU=Users:Main
        assert _extract_value("description: OU=Users:Main") == "OU=Users:Main"


# ── parse_ldap_users — comment-separated entries ────────────────────────

COMMENT_SEPARATED = """\
# jdoe, Users, example.com
dn: CN=jdoe,OU=Users,DC=example,DC=com
sAMAccountName: jdoe
displayName: John Doe
description: IT Admin

# asmith, Users, example.com
dn: CN=asmith,OU=Users,DC=example,DC=com
sAMAccountName: asmith
displayName: Alice Smith
description: Developer
"""


class TestCommentSeparated:
    def test_finds_all_users(self):
        users = parse_ldap_users(COMMENT_SEPARATED)
        assert len(users) == 2

    def test_correct_usernames(self):
        users = parse_ldap_users(COMMENT_SEPARATED)
        names = [u["username"] for u in users]
        assert names == ["jdoe", "asmith"]

    def test_fields_populated(self):
        users = parse_ldap_users(COMMENT_SEPARATED)
        assert users[0]["name"] == "John Doe"
        assert users[0]["description"] == "IT Admin"
        assert users[1]["name"] == "Alice Smith"


# ── parse_ldap_users — blank-line-separated entries (the original bug) ──

BLANK_LINE_SEPARATED = """\
dn: CN=jdoe,OU=Users,DC=example,DC=com
sAMAccountName: jdoe
displayName: John Doe

dn: CN=asmith,OU=Users,DC=example,DC=com
sAMAccountName: asmith
displayName: Alice Smith

dn: CN=bwilson,OU=Users,DC=example,DC=com
sAMAccountName: bwilson
displayName: Bob Wilson
"""


class TestBlankLineSeparated:
    def test_finds_all_users(self):
        """This was the original bug — blank-line-only separators were missed."""
        users = parse_ldap_users(BLANK_LINE_SEPARATED)
        assert len(users) == 3

    def test_correct_usernames(self):
        users = parse_ldap_users(BLANK_LINE_SEPARATED)
        names = [u["username"] for u in users]
        assert names == ["jdoe", "asmith", "bwilson"]

    def test_no_field_bleed(self):
        """Fields from one entry must not leak into the next."""
        users = parse_ldap_users(BLANK_LINE_SEPARATED)
        assert users[1]["name"] == "Alice Smith"
        assert users[2]["name"] == "Bob Wilson"


# ── parse_ldap_users — base64-encoded attributes ───────────────────────

def _b64(s):
    return base64.b64encode(s.encode()).decode()


BASE64_ENTRIES = f"""\
# José García
dn: CN=jgarcia,OU=Users,DC=example,DC=com
sAMAccountName: jgarcia
displayName:: {_b64("José García")}

# Müller
dn: CN=mmuller,OU=Users,DC=example,DC=com
sAMAccountName:: {_b64("mmüller")}
displayName:: {_b64("Max Müller")}
"""


class TestBase64Entries:
    def test_finds_all(self):
        users = parse_ldap_users(BASE64_ENTRIES)
        assert len(users) == 2

    def test_decoded_displayname(self):
        users = parse_ldap_users(BASE64_ENTRIES)
        assert users[0]["name"] == "José García"

    def test_decoded_username(self):
        users = parse_ldap_users(BASE64_ENTRIES)
        assert users[1]["username"] == "mmüller"
        assert users[1]["name"] == "Max Müller"


# ── parse_ldap_users — mixed real-world LDIF ────────────────────────────

REAL_WORLD_LDIF = """\
# extended LDIF
#
# LDAPv3
# base <DC=example,DC=com>
# filter: (&(objectClass=user)(objectCategory=person))
# requesting: sAMAccountName displayName description userPrincipalName
#

# jdoe, Users, example.com
dn: CN=jdoe,OU=Users,DC=example,DC=com
sAMAccountName: jdoe
userPrincipalName: jdoe@example.com
displayName: John Doe
description: IT Admin

# svc_backup, Service Accounts, example.com
dn: CN=svc_backup,OU=Service Accounts,DC=example,DC=com
sAMAccountName: svc_backup
userPrincipalName: svc_backup@example.com
description: Backup service account

# asmith, Users, example.com
dn: CN=asmith,OU=Users,DC=example,DC=com
sAMAccountName: asmith
userPrincipalName: asmith@example.com
displayName: Alice Smith

# search reference
ref: ldap://DomainDnsZones.example.com/DC=DomainDnsZones,DC=example,DC=com

# numResponses: 4
# numEntries: 3
# numReferences: 1
"""


class TestRealWorldLdif:
    def test_finds_all_users(self):
        users = parse_ldap_users(REAL_WORLD_LDIF)
        assert len(users) == 3

    def test_usernames(self):
        users = parse_ldap_users(REAL_WORLD_LDIF)
        names = [u["username"] for u in users]
        assert names == ["jdoe", "svc_backup", "asmith"]

    def test_upn_parsed(self):
        users = parse_ldap_users(REAL_WORLD_LDIF)
        assert users[0]["upn"] == "jdoe@example.com"

    def test_missing_displayname_ok(self):
        users = parse_ldap_users(REAL_WORLD_LDIF)
        svc = [u for u in users if u["username"] == "svc_backup"][0]
        assert "name" not in svc
        assert svc["description"] == "Backup service account"


# ── Edge cases ──────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_input(self):
        assert parse_ldap_users("") == []

    def test_no_users_just_metadata(self):
        text = "search: 2\nresult: 0 Success\n"
        assert parse_ldap_users(text) == []

    def test_entry_without_samaccountname_skipped(self):
        text = """\
dn: CN=group1,OU=Groups,DC=example,DC=com
displayName: Some Group
"""
        assert parse_ldap_users(text) == []

    def test_single_user_no_trailing_newline(self):
        text = "sAMAccountName: solo\ndisplayName: Solo User"
        users = parse_ldap_users(text)
        assert len(users) == 1
        assert users[0]["username"] == "solo"

    def test_multiple_blank_lines_between_entries(self):
        text = """\
sAMAccountName: user1
displayName: User One



sAMAccountName: user2
displayName: User Two
"""
        users = parse_ldap_users(text)
        assert len(users) == 2

    def test_dn_line_not_captured_as_field(self):
        text = """\
dn: CN=test,DC=example,DC=com
sAMAccountName: test
"""
        users = parse_ldap_users(text)
        assert "dn" not in users[0]


# ── main() CLI ──────────────────────────────────────────────────────────

class TestMainCli:
    def test_table_output(self):
        ldif = "sAMAccountName: jdoe\ndisplayName: John Doe\ndescription: admin\n"
        with patch("sys.stdin", io.StringIO(ldif)), \
             patch("sys.argv", ["ldapsearch_parse.py"]):
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                main()
            output = buf.getvalue()
            assert "jdoe" in output
            assert "John Doe" in output

    def test_wordlist_output(self):
        ldif = "sAMAccountName: jdoe\n\nsAMAccountName: asmith\n"
        with patch("sys.stdin", io.StringIO(ldif)), \
             patch("sys.argv", ["ldapsearch_parse.py", "-w"]):
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                main()
            lines = buf.getvalue().strip().splitlines()
            assert lines == ["jdoe", "asmith"]

    def test_output_to_file(self, tmp_path):
        ldif = "sAMAccountName: fileuser\ndisplayName: File User\n"
        outfile = str(tmp_path / "out.txt")
        with patch("sys.stdin", io.StringIO(ldif)), \
             patch("sys.argv", ["ldapsearch_parse.py", "-o", outfile]):
            main()
        content = open(outfile).read()
        assert "fileuser" in content
