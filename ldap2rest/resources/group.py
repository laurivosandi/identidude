import ldap
import re
from auth import authenticate
from util import serialize, domain2dn, dn2domain
import settings

class GroupResource:
    def __init__(self, conn):
        self.conn = conn

    @serialize
    @authenticate
    def on_get(self, req, resp, authenticated_user):
        group_fields = "gidNumber", "memberUid", "description"
        args = "ou=groups," + domain2dn(settings.BASE_DOMAIN), ldap.SCOPE_ONELEVEL, "objectClass=posixGroup", group_fields
        groups = dict()
        for dn, attributes in self.conn.search_s(*args):
            description = attributes.get("description").pop().decode("utf-8")
            m = re.match("cn=(?P<name>[a-z][a-z0-9]+),ou=groups,(?P<dn>.+)$", dn)
            name, dn = m.groups()
            if name in groups:
                print "Overlapping group names:", name
            if description.startswith("Group of user "):
                continue
            groups[name] = dict(
                name = name,
                description = description,
                gid = int(attributes.get("gidNumber").pop()),
                members = attributes.get("memberUid", []))

        return groups
