import argparse
import base64
import sys

FIELDS = {
    "sAMAccountName": "username",
    "userPrincipalName": "upn",
    "displayName": "name",
    "description": "description",
}

def _extract_value(line):
    """Handle both plain (attr: val) and base64-encoded (attr:: val) LDIF values."""
    attr, sep, value = line.partition(":")
    value = value.lstrip()
    if value.startswith(":"):
        # base64-encoded value (double colon)
        raw = value[1:].strip()
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return value

def parse_ldap_users(input_text):
    users = []
    current_user = {}

    for line in input_text.splitlines():
        line = line.strip()

        # Blank line or new comment block = end of current entry
        if line == "" or line.startswith("# "):
            if current_user and "username" in current_user:
                users.append(current_user)
                current_user = {}
            elif line.startswith("# "):
                current_user = {}
            continue

        # Skip LDIF metadata lines
        if line.startswith("dn:") or line.startswith("search:") or line.startswith("result:"):
            continue

        attr = line.split(":")[0]
        if attr in FIELDS:
            current_user[FIELDS[attr]] = _extract_value(line)

    # Save the last entry
    if "username" in current_user:
        users.append(current_user)

    return users


def main():
    ap = argparse.ArgumentParser(description="Parse ldapsearch output into a user table or wordlist.")
    ap.add_argument("-w", "--wordlist", action="store_true",
                    help="Output usernames only, one per line (wordlist mode)")
    ap.add_argument("-o", "--output", help="Write output to file instead of stdout")
    args = ap.parse_args()

    input_text = sys.stdin.read()
    users = parse_ldap_users(input_text)

    out = open(args.output, "w") if args.output else sys.stdout

    if args.wordlist:
        for u in users:
            print(u.get("username", ""), file=out)
    else:
        print(f"{'Username':<25} {'Full Name':<25} {'Notes'}", file=out)
        print("-" * 80, file=out)
        for u in users:
            username = u.get("username", "")
            name = u.get("name", "")
            desc = u.get("description", "")
            print(f"{username:<25} {name:<25} {desc}", file=out)

    if args.output:
        out.close()


if __name__ == "__main__":
    main()
