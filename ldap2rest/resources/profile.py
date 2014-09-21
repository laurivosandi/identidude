import ldap
import re
import falcon
from datetime import datetime, date, timedelta
from auth import authenticate, authorize_domain_admin
from util import serialize, domain2dn, dn2domain, apidoc
from forms import validate, RE_DATE, RE_EMAIL, RE_PHONE
from settings import \
    LDAP_BASE_DOMAIN, \
    LDAP_USER_ATTRIBUTE_ID, \
    LDAP_USER_ATTRIBUTE_USERNAME, \
    LDAP_USER_ATTRIBUTE_UID, \
    LDAP_USER_ATTRIBUTE_GID, \
    LDAP_USER_ATTRIBUTE_HOME_DIRECTORY, \
    LDAP_USER_ATTRIBUTE_BORN, \
    LDAP_USER_ATTRIBUTE_GENDER, \
    LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED
    

    

@apidoc
class ProfileResource:
    def __init__(self, conn):
        self.conn = conn

    @serialize
    @authenticate
    def on_get(self, req, resp, authenticated_user, domain=LDAP_BASE_DOMAIN, username=None):
        """
        Get user profile
        """
        if not re.match("[a-z][a-z0-9]{1,31}$", username):
            raise falcon.HTTPBadRequest("Error", "Invalid username")
            
        user_fields = "mobile", "gender", "dateOfBirth", "cn", "givenName", \
            "sn", "uid", "uidNumber", "gidNumber", "homeDirectory", \
            "modifyTimestamp", LDAP_USER_ATTRIBUTE_ID, LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED
            
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username, user_fields
        for dn, attributes in self.conn.search_s(*args):
            m = re.match("cn=(.+?),ou=people,(.+)$", dn)
            cn, dcs = m.groups()
            break
        else:
            raise falcon.HTTPNotFound()

#        days = attributes.get(LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED, ["b0"]).pop()
        days = int(attributes.get(LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED, ["0"]).pop())
        
        password_modified = date(1970,1,1) + timedelta(days=days) if days else None
#            : str((date.today() - date(1970,1,1)).days)

        return dict(
            id=attributes.get(LDAP_USER_ATTRIBUTE_ID, [None]).pop(),
            domain = dn2domain(dcs),
            cn = attributes.get("cn").pop().decode("utf-8"),
            born = attributes.get(LDAP_USER_ATTRIBUTE_BORN, [""]).pop(),
            gender = attributes.get(LDAP_USER_ATTRIBUTE_GENDER, [""]).pop(),
            username = attributes.get(LDAP_USER_ATTRIBUTE_USERNAME).pop(),
            uid = int(attributes.get(LDAP_USER_ATTRIBUTE_UID).pop()),
            gid = int(attributes.get(LDAP_USER_ATTRIBUTE_GID).pop()),
            home = attributes.get(LDAP_USER_ATTRIBUTE_HOME_DIRECTORY).pop(),
            password_modified = password_modified,
            #givenName = attributes.get("gn", [""]).pop().decode("utf-8"),
#            sn = attributes.get("sn", [""]).pop().decode("utf-8"),
            modified = datetime.strptime(attributes.get("modifyTimestamp").pop(), "%Y%m%d%H%M%SZ"))


    @serialize
    @authenticate
    @authorize_domain_admin
    @validate("born", RE_DATE, required=True)
    @validate("email", RE_EMAIL, required=True)
    @validate("mobile", RE_PHONE, required=True)
    def on_post(self, req, resp, authenticated_user, domain=LDAP_BASE_DOMAIN, username=None):
        """
        Edit profile
        """
        assert username, "No username specified"

    @serialize
    @authenticate
    @authorize_domain_admin
    def on_delete(self, req, resp, authenticated_user, domain=LDAP_BASE_DOMAIN, username=None):
        """
        Delete user
        """
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
            
        # TODO: Delete group memberships!

