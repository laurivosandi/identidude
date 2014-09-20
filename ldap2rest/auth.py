import falcon
import re
import Cookie
import hashlib
import random
import ldap
from util import dn2domain, domain2dn
from datetime import datetime
from settings import COOKIE_SECRET, COOKIE_LIFETIME, ADMINS, BASE_DOMAIN
import base64

class User(object):
    """
    LDAP user representation object, sort of ORM for LDAP
    """
    @classmethod
    def _get(cls, conn, dn, scope, filters):
        user_fields = "cn", "uid", "uidNumber", "gidNumber", "homeDirectory", "modifyTimestamp"
        args = dn, scope, filters, user_fields
        for dn, attributes in conn.search_s(*args):
            return cls(dn,
                username   = attributes.get("uid").pop(),
                uid        = int(attributes.get("uidNumber").pop()),
                gid        = int(attributes.get("gidNumber").pop()),
                home       = attributes.get("homeDirectory").pop(),
                cn         = attributes.get("cn", [None]).pop(),
                modified   = datetime.strptime(attributes.get("modifyTimestamp").pop(), "%Y%m%d%H%M%SZ"))
        else:
            raise falcon.HTTPForbidden(
                "Error",
                "Invalid username, it seems POSIX account with uid %s has been deleted" % username)


    @classmethod
    def get_by_dn(cls, conn, dn):
        # Do we need to validate DN here?
        return cls._get(conn, dn, ldap.SCOPE_BASE, "(objectClass=posixAccount)")

    @classmethod
    def get_by_uid(cls, conn, dn):
        return cls._get(conn, domain2dn(BASE_DOMAIN), ldap.SCOPE_SUBTREE, "(objectClass=posixAccount)")
    
    def __init__(self, dn, username, uid, gid, home, cn, modified):
        self.dn = dn
        m = re.match("cn=(.+?),ou=people,(.+)$", dn)
        self.cn, dcs = m.groups()
        self.domain = dn2domain(dcs)
        self.username = username
        self.uid = uid
        self.gid = gid
        self.cn = cn
        self.modified = modified
        
    def serialize(self):
        return dict(
            domain = self.domain,
            username = self.username,
            uid = self.uid,
            gid = self.gid,
            cn = self.cn)
        
    def generate_token(self, created=None):
        if not created:
            created = datetime.utcnow()
        expires = (created + COOKIE_LIFETIME)
        created = created.strftime("%s")
        digest = hashlib.sha1()
        digest.update(self.username)
        digest.update("|")
        digest.update(created)
        digest.update("|")
        digest.update(COOKIE_SECRET)
        return "%s,%s,%s" % (base64.b64encode(self.dn), created, digest.hexdigest()), expires

def authenticate(func):
    def wrapped(resource, req, resp, **kwargs):
        # Extract cookie
        cookie = req.get_header("Cookie")
        if not cookie:
            raise falcon.HTTPForbidden("Error", "No cookie sent")
        cookie = Cookie.SimpleCookie(cookie)
        
        try:
            token = cookie["token"].value
        except:
            raise falcon.HTTPForbidden("Error", "No token sent")

        # Validate cookie
        m = re.match("([a-z0-9A-Z\+\/]+={0,3}),(\d+),([0-9a-f]{32})", token)
        if not m:
            raise falcon.HTTPForbidden("Error", "Incorrectly formatted token")
        dn, created, digest = m.groups()

        # Get user profile by distinguished name as pointed out by cookie
        user = User.get_by_dn(resource.conn, base64.b64decode(dn))
        
        # Validate token hash
        created = datetime.fromtimestamp(int(created))
        reference_token, expires = user.generate_token(created)
        if  token != reference_token:
            raise falcon.HTTPForbidden("Error", "Invalid token")

        # Validate token timestamp
        if datetime.utcnow() > created + COOKIE_LIFETIME:
            raise falcon.HTTPForbidden("Error", "Token expired")

        # Inject authenticated_user keyword argument
        kwargs["authenticated_user"] = user
        
        # TODO: Update cookie?
            
        r = func(resource, req, resp, **kwargs)
        return r
    return wrapped
    
def authorize_domain_admin(func):
    """
    Authorize domain admins to call wrapped API call
    """
    def wrapped(instance, req, resp, **kwargs):
        authenticated_user = kwargs.get("authenticated_user", None)
        requested_domain = kwargs.get("domain", None)
        
        if not authenticated_user:
            raise falcon.HTTPForbidden("Error", "User not authenticated")
        if not requested_domain:
            raise falcon.HTTPForbidden("Error", "No requested domain specified")

        managed_domain = ADMINS.get(authenticated_user.username, None)
        
        if not managed_domain:
            raise falcon.HTTPForbidden("Error", "Not admin at all")
            
        if requested_domain == managed_domain:
            # I am admin of this domain
            pass
        elif requested_domain.endswith("." + managed_domain):
            # I am admin of the superdomain
            pass
        else:
            raise falcon.HTTPForbidden("Error", "Not domain admin")
        r = func(instance, req, resp, **kwargs)
        return r
    return wrapped
    
def authorize_owner(func):
    """
    Authorize owned resource identified by username
    """
    def wrapped(instance, req, resp, **kwargs):
        authenticated_user = kwargs.get("authenticated_user", None)
        requested_user = kwargs.get("user", None)
        if not authenticated_user:
            raise falcon.HTTPBadRequest("Error", "Not authenticated")
        if not requested_username:
            raise falcon.HTTPBadRequest("Error", "No requested user specified")
        if requested_username != authenticated_user:
            raise falcon.HTTPBadRequest("Error", "Trying to access resource not owned by user")

        r = func(instance, req, resp, **kwargs)
        return r
    return wrapped
    
def generate_password(length):
    return ''.join(random.sample("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789", length))
