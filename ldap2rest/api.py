#!/usr/bin/python
# encoding: utf-8

"""
This is stand-alone application for LDAP to RESTful-HTTP bridge.
In your web-server mount it at /api/ and serve / from static/.
"""

import falcon
import ldap
import settings
from resources.session import SessionResource
from resources.group import GroupResource
from resources.ssh import AuthorizedKeysResource
from resources.lookup import LookupResource
from resources.user import UserListResource
from resources.profile import ProfileResource
from resources.shadow import PasswordResource
from resources.domain import DomainListResource
from mailer import Mailer

conn = ldap.init(settings.LDAP_SERVER)
conn.simple_bind_s(settings.LDAP_ADMIN_DN, settings.LDAP_ADMIN_PASS)

if settings.DEBUG:
    # Give neat debug output!
    def debug_search_s(oldfunc):
        def patched(base, scope, filterstr="(objectClass=*)", attrlist=None, attrsonly=0):
            print "ldapsearch -h %s -x -b '%s' -s %s %s %s" % (settings.LDAP_SERVER, base, ("base", "onelevel", "subtree")[scope], repr(filterstr), " ".join(attrlist or ()))
            return oldfunc(base, scope, filterstr, attrlist, attrsonly)
        return patched
        
    def debug_delete_s(oldfunc):
        def patched(dn):
            print "ldapdelete -h %s -x -b '%s'" % (settings.LDAP_SERVER, dn)
            oldfunc(dn)
        return patched
            
    conn.search_s = debug_search_s(conn.search_s)
    conn.delete_s = debug_delete_s(conn.delete_s)

mailer = Mailer(
    settings.SMTP_SERVER,
    port=getattr(settings, "SMTP_PORT", 25),
    secure=getattr(settings, "SMTP_SECURE", False),
    username=getattr(settings, "SMTP_USERNAME", ""),
    password=getattr(settings, "SMTP_PASSWORD", ""))

app = falcon.API(after=[])
app.add_route("/session/", SessionResource(conn, admins=settings.ADMINS))
app.add_route("/authorized_keys/", AuthorizedKeysResource(conn))
app.add_route("/group/", GroupResource(conn))
app.add_route("/domain/", DomainListResource(conn))
app.add_route("/domain/{domain}/user/", UserListResource(conn, mailer))
app.add_route("/domain/{domain}/user/{username}/", ProfileResource(conn))
app.add_route("/domain/{domain}/user/{username}/password/", PasswordResource(conn, mailer))
app.add_route("/domain/{domain}/authorized_keys/", AuthorizedKeysResource(conn))
app.add_route("/lookup/", LookupResource())

if __name__ == '__main__':
    from wsgiref import simple_server
    httpd = simple_server.make_server('0.0.0.0', 8000, app)
    httpd.serve_forever()
