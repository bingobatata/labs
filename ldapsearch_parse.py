import argparse
import sys

def parse_ldap_users(input_text):
    users = []
    current_user = {}

    for line in input_text.splitlines():
        line = line.strip()

        if line.startswith("sAMAccountName:"):
            current_user["username"] = line.split(":", 1)[1].strip()

        elif line.startswith("userPrincipalName:"):
            current_user["upn"] = line.split(":", 1)[1].strip()

        elif line.startswith("displayName:"):
            current_user["name"] = line.split(":", 1)[1].strip()

        elif line.startswith("description:"):
            current_user["description"] = line.split(":", 1)[1].strip()

        # When we hit a new entry, save the previous one
        elif line.startswith("# ") and current_user:
            if "username" in current_user:
                users.append(current_user)
            current_user = {}

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
