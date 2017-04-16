
from configparser import ConfigParser
cp = ConfigParser()
cp.read("/etc/samba/smb.conf")
REALM = cp.get("global", "realm") # EXAMPLE.LAN
DOMAIN = REALM.lower() # example.lan
NAME = cp.get("global", "netbios name") # ID
LDAP_BASEDN = ",".join(["dc=" + dc for dc in DOMAIN.split(".")]) # dc=example,dc=lan
LDAP_URI = "ldap://%s" % DOMAIN # ldap://example.lan

# TODO: Make configurable via /etc/identidude.conf
LDAP_RECOVERY_EMAIL = "otherMailbox"
MAIL_DOMAIN = DOMAIN.replace(".lan", ".com")
MAIL_SERVER = "mail." + MAIL_DOMAIN
