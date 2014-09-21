import ldap
import re
from auth import authenticate
from util import serialize, domain2dn, dn2domain, apidoc
from settings import \
    LDAP_BASE_DOMAIN, \
    LDAP_GROUP_ATTRIBUTE_GID, \
    LDAP_GROUP_ATTRIBUTE_MEMBER_USERNAME, \
    LDAP_GROUP_ATTRIBUTE_DESCRIPTION

@apidoc
class GroupResource:
    def __init__(self, conn):
        self.conn = conn

    @serialize
    @authenticate
    def on_get(self, req, resp, authenticated_user):
        group_fields = \
            LDAP_GROUP_ATTRIBUTE_GID, \
            LDAP_GROUP_ATTRIBUTE_MEMBER_USERNAME, \
            LDAP_GROUP_ATTRIBUTE_DESCRIPTION
        
        args = "ou=groups," + domain2dn(LDAP_BASE_DOMAIN), ldap.SCOPE_ONELEVEL, "objectClass=posixGroup", group_fields
        groups = dict()
        for dn, attributes in self.conn.search_s(*args):
            description = attributes.get(LDAP_GROUP_ATTRIBUTE_DESCRIPTION).pop().decode("utf-8")
            m = re.match("cn=(?P<name>[a-z][a-z0-9]+),ou=groups,(?P<dn>.+)$", dn)
            name, dn = m.groups()
            if name in groups:
                print "Overlapping group names:", name
            if description.startswith("Group of user "):
                continue
            groups[name] = dict(
                name = name,
                description = description,
                gid = int(attributes.get(LDAP_GROUP_ATTRIBUTE_GID).pop()),
                members = attributes.get(LDAP_GROUP_ATTRIBUTE_MEMBER_USERNAME, []))

        return groups
