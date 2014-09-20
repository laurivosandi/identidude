import falcon
import ldap
from datetime import datetime
from util import domain2dn, dn2domain, serialize
from auth import authenticate, User
from forms import validate
from settings import BASE_DOMAIN, LDAP_SERVER, COOKIE_LIFETIME, ADMINS

class SessionResource:
    def __init__(self, conn, admins):
        self.conn = conn
        self.admins = admins
        
    def find_user(self, username):
        user_fields = "cn", "uid", "uidNumber", "gidNumber", "homeDirectory", "modifyTimestamp"
        args = domain2dn(BASE_DOMAIN), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username, user_fields
        for dn, attributes in self.conn.search_s(*args):
            user = dict()
            user["id"]         = attributes.get("employeeNumber", [None]).pop()
            user["born"]       = attributes.get("dateOfBirth", [None]).pop()
            user["username"]   = attributes.get("uid").pop()
            user["uid"]        = int(attributes.get("uidNumber").pop())
            user["gid"]        = int(attributes.get("gidNumber").pop())
            user["home"]       = attributes.get("homeDirectory").pop()
            user["cn"]         = attributes.get("cn", [None]).pop()
            user["modified"]   = datetime.strptime(attributes.get("modifyTimestamp").pop(), "%Y%m%d%H%M%SZ")
            break
        else:
            raise falcon.HTTPForbidden(
                "Error",
                "Invalid username, could not lookup POSIX account with uid %s" % username)
        return dn, user

    @serialize
    @authenticate
    def on_get(self, req, resp, authenticated_user):
        return self._get_profile(authenticated_user)

    @serialize
    @validate("username",  r"[a-z][a-z0-9]{1,31}$", required=True)
    @validate("password",  r"[A-Za-z0-9@#$%^&+=]{8,}$") 
    def on_post(self, req, resp):
        username = req.get_param("username").encode("ascii")
        password = req.get_param("password").encode("ascii")
        
        if not username or not password:
            raise falcon.HTTPUnauthorized("Error", "No username or password supplied")

        authorized_user = User.get_by_uid(self.conn, username)

        auth_conn = ldap.init(LDAP_SERVER)
        try:
            print "Attempting bind with dn:", authorized_user.dn
            auth_conn.simple_bind_s(authorized_user.dn, password)
        except ldap.INVALID_CREDENTIALS:
            raise falcon.HTTPUnauthorized("Error", "Invalid password, failed to do simple bind against LDAP server with specified username and password")
            
        
        token, expires = authorized_user.generate_token()
        resp.set_header("Set-Cookie", "token=%s; Expires=%s; Path=/api/;" % (token, expires.strftime("%a, %d %b %Y %T %Z")))
        return self._get_profile(authorized_user)
        
    def _get_profile(self, user):
        u = user.serialize()
        # List authorized domains
        domain = self.admins.get(user.username, None)
        if domain:
            managed_domains = self.conn.search_s(domain2dn(domain), ldap.SCOPE_SUBTREE, "(objectClass=domain)", ["description"])
            managed_domains = dict([(dn2domain(dcs), a["description"].pop()) for dcs, a in managed_domains])
            if domain == BASE_DOMAIN:
                managed_domains[BASE_DOMAIN] = "All organizations"
            u["managed_domains"] = managed_domains
        return u

        
