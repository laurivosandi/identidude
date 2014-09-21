import ldap
from util import domain2dn, serialize, apidoc
from forms import validate
from auth import authenticate, authorize_owner
from settings import \
    LDAP_BASE_DOMAIN, \
    LDAP_USER_ATTRIBUTE_USERNAME, \
    LDAP_USER_ATTRIBUTE_AUTHORIZED_KEYS, \
    LDAP_USER_ATTRIBUTE_HOME_DIRECTORY

@apidoc
class AuthorizedKeysResource:
    def __init__(self, conn):
        self.conn = conn

    @serialize
    @authenticate
    def on_get(self, req, resp, domain=LDAP_BASE_DOMAIN):
        """
        Retrieve SSH keys corresponding to users
        """
        username = req.get_param("username")
        if username:
            query = "(&(objectClass=posixAccount)(%s=%s))" % (LDAP_USER_ATTRIBUTE_USERNAME, username)
        else:
            query = "objectClass=posixAccount"
        user_fields = \
            LDAP_USER_ATTRIBUTE_USERNAME, \
            LDAP_USER_ATTRIBUTE_AUTHORIZED_KEYS, \
            LDAP_USER_ATTRIBUTE_HOME_DIRECTORY
        args = domain2dn(LDAP_BASE_DOMAIN), ldap.SCOPE_SUBTREE, query, user_fields
        r = dict()
        for dn, attributes in self.conn.search_s(*args):
            keys = attributes.get(LDAP_USER_ATTRIBUTE_AUTHORIZED_KEYS, [])
            if not keys:
                continue
            r[attributes[LDAP_USER_ATTRIBUTE_USERNAME].pop()] = {"authorized_keys": keys, "home": attributes[LDAP_USER_ATTRIBUTE_HOME_DIRECTORY].pop()}
        return r

    @serialize
    @authenticate
    @validate("pubkey", "[A-Za-z0-9 /+@_]+$")
    def on_post(self, req, resp, authenticated_user, domain=LDAP_BASE_DOMAIN):
        pass
