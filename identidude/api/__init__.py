# encoding: utf-8

import click
import falcon
import ldap, ldap.sasl
import mimetypes
import os
import struct
from datetime import datetime, timedelta
from identidude.decorators import login_required, serialize, ldap_connect
from identidude import config
from .ssh import AuthorizedKeysResource
from .lookup import LookupResource
from .cert import CertificateResource
from .mail import MailAliasResource
from .user import UserListResource, ProfileResource, ad_time


# curl --negotiate -u : --delegation always id.example.lan/api | jq

class SessionResource(object):
    @serialize
    @login_required(delegate_credentials=True)
    @ldap_connect
    def on_get(self, req, resp, conn):
        # Extract domain attribute
        for dn, domain in conn.search_s(config.LDAP_BASEDN, ldap.SCOPE_BASE):
            if not dn: continue
            max_pwd_age = int(domain.get("maxPwdAge").pop())
            if max_pwd_age == -9223372036854775808:
                password_lifetime = None # Password doesn't expire
            else:
                password_lifetime = -max_pwd_age / 10000000 # dafuq
            break
        else:
            raise # no domain, dafuq?

        group_by_dn = dict()
        group_by_rid = dict()

        def list_groups():
            attribs = 'sAMAccountName', 'objectSid', 'description', 'sAMAccountType', \
                "whenChanged", "whenCreated"
            search_filter = '(&(objectClass=group))'
            r = conn.search_s(config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, search_filter, attribs)
            for dn,entry  in r:
                if not dn: continue
                sid, = entry.get("objectSid")
                rid, = struct.unpack("i", sid[-4:])
                group = dict()
                group["created"] = datetime.strptime(entry.get("whenCreated").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")
                group["changed"] = datetime.strptime(entry.get("whenChanged").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")

                group["name"], = entry.get("sAMAccountName")
                try:
                    group["description"], = entry.get("description")
                except TypeError:
                    pass
                group_by_dn[dn] = group_by_rid[rid] = group["name"]
                bitmap = int(entry.get("sAMAccountType")[0])
                group["type"] = "group" if bitmap & 0x10000000 else "other"
                group["rid"] = rid
                yield group

        def list_computers():
            attribs = "sAMAccountName", "dNSHostName", "servicePrincipalName", \
                "whenChanged", "whenCreated", \
                "operatingSystem", "operatingSystemVersion", "userAccountControl"
            search_filter = '(&(objectClass=user)(objectCategory=computer))'
            r = conn.search_s(config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, search_filter, attribs)
            for dn,entry in r:
                if not dn: continue
                computer = dict()
                computer["created"] = datetime.strptime(entry.get("whenCreated").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")
                computer["changed"] = datetime.strptime(entry.get("whenChanged").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")
                computer["locked"] = bool(int(entry.get("userAccountControl")[0]) & 2)

                os = entry.get("operatingSystem", [b""]).pop().decode("utf-8")
                if os:
                    computer["os"] = os
                    computer["os_version"], = entry.get("operatingSystemVersion", (None,))
                if "linux" in os or "Samba" in os:
                    computer["os_type"] = "linux"
                elif "Mac OS X" in os:
                    computer["os_type"] = "apple"
                elif "Windows" in os:
                    computer["os_type"] = "windows"

                computer["name"] = entry.get("sAMAccountName").pop()[:-1]
                computer["fqdn"], = entry.get("dNSHostName")
                computer["service_principals"] = entry.get("servicePrincipalName")
                yield computer

        def list_users():
            attribs = 'mail', 'userPrincipalName', 'sAMAccountName', "givenName", \
                "sn", "userAccountControl", "memberOf", "primaryGroupID", \
                "whenChanged", "whenCreated", \
                "accountExpires", "pwdLastSet", "lastLogon", "sAMAccountType"
            search_filter = '(&(objectClass=user)(objectCategory=person))'
            r = conn.search_s(config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, search_filter, attribs)

            for dn,entry in r:
                if not dn: continue
                user = dict()
                user["name"], = entry.get("sAMAccountName")
                user["created"] = datetime.strptime(entry.get("whenCreated").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")
                user["changed"] = datetime.strptime(entry.get("whenChanged").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")
                user["locked"] = bool(int(entry.get("userAccountControl")[0]) & 2)
                user["normal"] = bool(int(entry.get("sAMAccountType")[0]) & 0x30000000)
                user["last_login"] = ad_time(entry.get("lastLogon").pop())
                user["expires"] = ad_time(entry.get("accountExpires").pop())
                user["password_set"] = ad_time(entry.get("pwdLastSet").pop())

                if password_lifetime and user["password_set"]:
                    user["password_expires"] = bool(int(entry.get("userAccountControl")[0]) & 0x10000)

                try:
                    user["gn"], = entry.get("givenName")
                    user["sn"], = entry.get("sn")
                except TypeError:
                    pass

                try:
                    user["mail"], = entry.get("mail")
                except TypeError:
                    pass

                user["groups"] = [group_by_dn[dn.decode("utf-8")] for dn in (entry.get("memberOf") or ())]
                user["groups"].append(group_by_rid[int(entry.get("primaryGroupID")[0])])
                yield user
        return dict(
            domain = dict(
                max_password_age = password_lifetime
            ),
            computers = tuple(list_computers()),
            groups = tuple(list_groups()),
            users = tuple(list_users()))


class StaticResource(object):
    def __init__(self, root):
        self.root = os.path.realpath(root)

    def __call__(self, req, resp):
        path = os.path.realpath(os.path.join(self.root, req.path[1:]))
        if not path.startswith(self.root):
            raise falcon.HTTPForbidden

        if os.path.isdir(path):
            path = os.path.join(path, "index.html")
        click.echo("Serving: %s" % path)

        if os.path.exists(path):
            content_type, content_encoding = mimetypes.guess_type(path)
            if content_type:
                resp.append_header("Content-Type", content_type)
            if content_encoding:
                resp.append_header("Content-Encoding", content_encoding)
            resp.stream = open(path, "rb")
        else:
            resp.status = falcon.HTTP_404
            resp.body = "File '%s' not found" % req.path


app = falcon.API()
app.add_route("/api/", SessionResource())
app.add_route("/api/user/", UserListResource())
app.add_route("/api/user/{username}/", ProfileResource())
app.add_route("/api/lookup/", LookupResource())
app.add_route("/api/{username}.pem", CertificateResource()) # Get user certificates
app.add_route("/api/{samaccountname}.keys", AuthorizedKeysResource()) # Get SSH keys of users/groups
app.add_route("/api/aliases/", MailAliasResource())
app.add_sink(StaticResource(os.path.join(__file__, "..", "..", "static")))
