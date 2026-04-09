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
    input_text = sys.stdin.read()
    users = parse_ldap_users(input_text)

    print(f"{'Username':<25} {'Full Name':<25} {'Notes'}")
    print("-" * 80)
    for u in users:
        username = u.get("username", "")
        name = u.get("name", "")
        desc = u.get("description", "")
        print(f"{username:<25} {name:<25} {desc}")


if __name__ == "__main__":
    main()
