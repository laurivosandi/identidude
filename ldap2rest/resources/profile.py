import ldap
import re
import falcon
from resources.auth import auth
from util import serialize, domain2dn, dn2domain
import settings


class ProfileResource:
    def __init__(self, conn):
        self.conn = conn

    @serialize
    def on_get(self, req, resp, domain=settings.BASE_DOMAIN, username=None):
        if not re.match("[a-z][a-z0-9]{1,31}$", username):
            raise falcon.HTTPBadRequest("Error", "Invalid username")
            
        user_fields = "mobile", "gender", "dateOfBirth", "cn", "givenName", \
            "sn", "uid", "uidNumber", "gidNumber", "homeDirectory", \
            "modifyTimestamp", settings.LDAP_USER_ATTRIBUTE_ID
            
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username, user_fields
        for dn, attributes in self.conn.search_s(*args):
            m = re.match("cn=(.+?),ou=people,(.+)$", dn)
            cn, dcs = m.groups()
            print "Leidsin:", dn, attributes
            break
        else:
            raise falcon.HTTPNotFound()

        return dict(
            id=attributes.get(settings.LDAP_USER_ATTRIBUTE_ID, [None]).pop(),
            domain = dn2domain(dcs),
            born = attributes.get("dateOfBirth", [""]).pop(),
            username = attributes.get("uid").pop(),
            uid = int(attributes.get("uidNumber").pop()),
            gid = int(attributes.get("gidNumber").pop()),
            home = attributes.get("homeDirectory").pop(),
            givenName = attributes.get("gn", [""]).pop().decode("utf-8"),
            sn = attributes.get("sn", [""]).pop().decode("utf-8"),
            cn = attributes.get("cn").pop().decode("utf-8"),
            modified = datetime.strptime(attributes.get("modifyTimestamp").pop(), "%Y%m%d%H%M%SZ"))

    def on_post(self, req, resp, domain=settings.BASE_DOMAIN, username=None):
        assert username, "No username specified"


    def on_delete(self, req, resp, domain=settings.BASE_DOMAIN, username=None):
        # Validate username, TODO: in middleware
        if not re.match("[a-z][a-z0-9]{1,31}$", username):
            raise falcon.HTTPBadRequest("Error", "Invalid username")
        
        # Find distinguished name corresponding to username
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username,
        for dn, attributes in self.conn.search_s(*args):
            break
        else:
            raise falcon.HTTPNotFound()

        # Delete group if necessary
        try:
            self.conn.delete_s("cn=%s,ou=groups,%s" % (username, domain2dn(domain)))
        except ldap.NO_SUCH_OBJECT:
            pass
        except ldap.LDAPError, e:
            raise falcon.HTTPBadRequest(e.message.get("info"), e.message.get("desc"))

        # Delete user
        try:
            self.conn.delete_s(dn)
        except ldap.LDAPError, e:
            raise falcon.HTTPBadRequest(e.message.get("info"), e.message.get("desc"))

