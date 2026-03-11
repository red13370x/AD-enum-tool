import argparse
import ssl
from ldap3 import Server, Connection, ALL, Tls, NTLM  #type: ignore 

banner = """
Active Directory Enumeration Tool - Version 2.0 tung tung tung sahuar edition 
"""
print(banner)


def connect_to_ldap(dc_ip, username, password):
    """
    try connecting to LDAP using plain LDAP
    """

    print("[*] trying plain LDAP (389)...")

    try:
        server = Server(dc_ip, port=389, get_info=ALL)

        conn = Connection(
            server,
            user=username,
            password=password,
            authentication=NTLM
        )

        if conn.bind():
            print(f"[+] connected using {username}")
            return conn
        else:
            print("[-] bind failed")
            print(conn.result)
            return None

    except Exception as e:
        print("[-] connection error:", e)
        return None


def get_base_dn(conn):
    """
    Get the base DN from the domain controller
    """

    try:
        base_dn = conn.server.info.other["defaultNamingContext"][0]
        return base_dn
    except Exception:
        print("[-] could not get base DN")
        return None


def enumerate_users(conn, base_dn):
    """
    Search LDAP for users and print useful flags
    """

    print("[+] enumerating users...")

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer)))",
        attributes=[
            "sAMAccountName",
            "servicePrincipalName",
            "adminCount",
            "userAccountControl"
        ]
    )

    for entry in conn.entries:

        try:
            username = str(entry.sAMAccountName)
        except Exception:
            continue

        flags = []

        #check for SPN (kerberoastable accounts)
        if hasattr(entry, "servicePrincipalName"):
            if entry.servicePrincipalName:
                flags.append("SPN")

        #check for admin accounts
        if hasattr(entry, "adminCount"):
            if str(entry.adminCount) == "1":
                flags.append("admin-count")

        #check password never expires
        if hasattr(entry, "userAccountControl"):
            try:
                uac = int(entry.userAccountControl.value)
                if uac & 0x10000:
                    flags.append("password-never-expires")
            except Exception:
                pass

        if flags:
            print(f"[!] {username} -> {', '.join(flags)}")
        else:
            print(f"[*] {username}")


def main():

    parser = argparse.ArgumentParser(description="SPN means it could possibly be kerberoastable, admin-count means the account is likely privileged, password never expires is self explanitory")

    parser.add_argument("--dc", required=True, help="domain controller IP or hostname")
    parser.add_argument("--user", required=True, help="domain.local\\username")
    parser.add_argument("--password", required=True, help="password")
    
    
    args = parser.parse_args()

    print("[*] connecting to LDAP server")

    conn = connect_to_ldap(args.dc, args.user, args.password)

    if not conn:
        print("[-] could not connect or authenticate")
        return

    print("[+] authentication successful")

    base_dn = get_base_dn(conn)

    if not base_dn:
        return

    print(f"[+] using base DN: {base_dn}")

    enumerate_users(conn, base_dn)

    conn.unbind()
    
    x = "shout out to my homie tung tung tung sahuar for the name of this edition"
    print(f"[+] {x}")


if __name__ == "__main__":
    main()