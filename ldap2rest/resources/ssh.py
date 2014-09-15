import ldap
from util import domain2dn, serialize
from settings import BASE_DOMAIN

class AuthorizedKeysResource:
    def __init__(self, conn):
        self.conn = conn

    @serialize
    def on_get(self, req, resp, domain=BASE_DOMAIN):
        """
        Retrieve SSH keys corresponding to users
        """
        username = req.get_param("username")
        if username:
            query = "(&(objectClass=posixAccount)(uid=%s))" % username
        else:
            query = "objectClass=posixAccount"
        args = domain2dn(BASE_DOMAIN), ldap.SCOPE_SUBTREE, query, ["sshPublicKey", "uid", "homeDirectory"]
        r = dict()
        for dn, attributes in self.conn.search_s(*args):
            keys = attributes.get("sshPublicKey", [])
            if not keys:
                continue
            r[attributes["uid"].pop()] = {"authorized_keys": keys, "home": attributes["homeDirectory"].pop()}
        return r

    @serialize
    def on_post(self, req, resp, domain=BASE_DOMAIN):
        pass
