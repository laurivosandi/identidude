import falcon
import ldap
import re
import Cookie
from datetime import datetime
from util import domain2dn, dn2domain, generate_token, serialize
from settings import BASE_DOMAIN, LDAP_SERVER, COOKIE_LIFETIME, ADMINS

def auth(func):
    def wrapped(instance, req, resp, **kwargs):
        cookie = req.get_header("Cookie")
        if not cookie:
            raise falcon.HTTPForbidden("Error", "No cookie sent")
        cookie = Cookie.SimpleCookie(cookie)
        try:
            token = cookie["token"].value
        except:
            raise falcon.HTTPForbidden("Error", "No token sent")
        m = re.match("([a-z][a-z0-9]*),(\d+),([0-9a-f]{32})", token)
        if not m:
            raise falcon.HTTPForbidden("Error", "Incorrectly formatted token")
            
        username, created, digest = m.groups()
        req._params["username"] = username
        created = datetime.fromtimestamp(int(created))
        if generate_token(username, created) != token:
            raise falcon.HTTPForbidden("Error", "Invalid token")

        if  datetime.utcnow() > created + COOKIE_LIFETIME:
            raise falcon.HTTPForbidden("Error", "Token expired")

        # Authorization
        if "domain" in kwargs:
            domain = ADMINS.get(username, None)
            if not domain:
                raise falcon.HTTPForbidden("Error", "Not domain admin")
            if domain == kwargs["domain"]:
                # I am admin of this domain
                pass
            elif kwargs["domain"].endswith("." + domain):
                # I am admin of the superdomain
                pass
            else:
                raise falcon.HTTPForbidden("Error", "Not domain admin")
        
        r = func(instance, req, resp, **kwargs)
        return r
    return wrapped
    

class SessionResource:
    def __init__(self, conn, admins):
        self.conn = conn
        self.admins = admins
        
    def find_user(self, username):
        user_fields = "cn", "uid", "uidNumber", "gidNumber", "homeDirectory", "modifyTimestamp"
        args = domain2dn(BASE_DOMAIN), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username, user_fields
        for dn, attributes in self.conn.search_s(*args):
            user = dict()
#            user["id"]         = attributes.get("employeeNumber", [None]).pop()
#            user["born"]       = attributes.get("dateOfBirth", [None]).pop()
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
            
        # List authorized domains
        domain = self.admins.get(user["username"], None)
        if domain:
            managed_domains = self.conn.search_s(domain2dn(domain), ldap.SCOPE_SUBTREE, "(objectClass=domain)", ["description"])
            managed_domains = dict([(dn2domain(dcs), a["description"].pop()) for dcs, a in managed_domains])
            if domain == BASE_DOMAIN:
                managed_domains[BASE_DOMAIN] = "All organizations"
            user["managed_domains"] = managed_domains
            
        return dn, user

    @auth
    @serialize
    def on_get(self, req, resp):
        username = req.get_param("username")
        assert username
        dn, profile = self.find_user(username)
        return profile

    @serialize
    def on_post(self, req, resp):
        username = req.get_param("username")
        password = req.get_param("password")
        
        if not username or not password:
            raise falcon.HTTPUnauthorized("Error", "No username or password supplied")

        dn, user = self.find_user(username)

        auth_conn = ldap.init(LDAP_SERVER)
        try:
            print "Attempting bind with dn:", dn
            auth_conn.simple_bind_s(dn, password)
        except ldap.INVALID_CREDENTIALS:
            raise falcon.HTTPUnauthorized("Error", "Invalid password, failed to do simple bind against LDAP server with specified username and password")

        now = datetime.utcnow()
        expires = (now + COOKIE_LIFETIME).strftime("%a, %d %b %Y %T %Z")
        token = generate_token(username, now)
        resp.set_header("Set-Cookie", "token=%s; Expires=%s; Path=/api/;" % (token, expires))
        return user
        
