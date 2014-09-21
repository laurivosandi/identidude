import falcon
import ldap
from datetime import datetime
from util import domain2dn, dn2domain, serialize
from auth import authenticate, authorize_owner, User
from forms import validate, \
    RE_USERNAME, \
    RE_PHONE, \
    RE_DATE, \
    RE_PASSWORD, \
    RE_EMAIL
from settings import COOKIE_LIFETIME, ADMINS, \
    LDAP_SERVER, \
    LDAP_BASE_DOMAIN, \
    LDAP_USER_ATTRIBUTE_ID, \
    LDAP_USER_ATTRIBUTE_USERNAME, \
    LDAP_USER_ATTRIBUTE_UID, \
    LDAP_USER_ATTRIBUTE_GID, \
    LDAP_USER_ATTRIBUTE_HOME_DIRECTORY, \
    LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, \
    LDAP_USER_ATTRIBUTE_BORN, \
    LDAP_USER_ATTRIBUTE_GENDER, \
    LDAP_USER_ATTRIBUTE_MOBILE


class SessionResource:
    def __init__(self, conn, admins):
        self.conn = conn
        self.admins = admins

    @serialize
    @validate("username",  RE_USERNAME)
    @validate("password",  RE_PASSWORD) 
    def on_post(self, req, resp):
        username = req.get_param("username").encode("ascii")
        password = req.get_param("password").encode("ascii")
        
        if not username or not password:
            raise falcon.HTTPUnauthorized("Error", "No username or password supplied")

        user = User.get_by_uid(self.conn, username)

        auth_conn = ldap.init(LDAP_SERVER)
        try:
            print "Attempting bind with dn (uid=%s): %s %s" % (username, repr(user.dn), repr(password))
            auth_conn.simple_bind_s(user.dn.encode("utf-8"), password)
        except ldap.INVALID_CREDENTIALS:
            raise falcon.HTTPUnauthorized("Error", "Invalid password, failed to do simple bind against LDAP server with specified username and password")
            
        
        token, expires = user.generate_token()
        resp.set_header("Set-Cookie", "token=%s; Expires=%s; Path=/api/;" % (token, expires.strftime("%a, %d %b %Y %T %Z")))
        return self._get_profile(user)

    @serialize
    @authenticate
    def on_get(self, req, resp, authenticated_user):
        return self._get_profile(authenticated_user)

    @serialize
    @authenticate
    @validate("email", RE_EMAIL)
    @validate("mobile", RE_PHONE)
    @validate("born", RE_DATE)
    @validate("gender", "(F|M)$")
    def on_put(self, req, resp, authenticated_user):
        """
        Edit own profile
        """
        entry = \
            (ldap.MOD_REPLACE, LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, req.get_param("email").encode("utf-8")), \
            (ldap.MOD_REPLACE, LDAP_USER_ATTRIBUTE_MOBILE, req.get_param("mobile").encode("utf-8")), \
            (ldap.MOD_REPLACE, LDAP_USER_ATTRIBUTE_BORN, req.get_param("born").encode("utf-8")), \
            (ldap.MOD_REPLACE, LDAP_USER_ATTRIBUTE_GENDER, req.get_param("gender").encode("utf-8"))
        self.conn.modify_s(authenticated_user.dn.encode("utf-8"), entry)
        
    def _get_profile(self, user):
        u = user.serialize()
        # List authorized domains
        domain = self.admins.get(user.username, None)
        if domain:
            managed_domains = self.conn.search_s(domain2dn(domain), ldap.SCOPE_SUBTREE, "(objectClass=domain)", ["description"])
            managed_domains = dict([(dn2domain(dcs), a["description"].pop()) for dcs, a in managed_domains])
            if domain == LDAP_BASE_DOMAIN:
                managed_domains[LDAP_BASE_DOMAIN] = "All organizations"
            u["managed_domains"] = managed_domains if managed_domains else None
        return u

        
