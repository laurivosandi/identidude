# encoding: utf-8

import hashlib
import falcon
import ldap
import os
import random
import re
import string
from base64 import b64decode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from datetime import datetime, date, timedelta
from ldap import modlist
from identidude import config
from identidude.decorators import serialize, login_required, apidoc, ldap_connect
from identidude.forms import validate, required, \
    RE_USERNAME, RE_CHECKBOX, RE_DATE, RE_EMAIL, RE_PHONE


def serialize_subject(subj):
    return "".join(["/%s=%s" % (j.oid._name, j.value) for j in subj])


def serialize_cert(cert):
    common_name, = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return dict(
        common_name = common_name.value,
        subject = serialize_subject(cert.subject),
        issuer = serialize_subject(cert.issuer),
        serial = "%x" % cert.serial,
        signed = cert.not_valid_before,
        expires = cert.not_valid_after)


def ad_time(b):
    i = int(b)
    if i == 9223372036854775807 or i == 0:
        return None
    return datetime.utcfromtimestamp(-11644473600 + (int(b) / 10000000.0)) # wth are you smoking guys 100ns intervals since 1601 jan 1


class ProfileResource(object):
    @serialize
    @ldap_connect
    def on_get(self, req, resp, conn, username):
        search_filter = '(&(objectClass=user)(objectCategory=person)(samaccountname=%s))' % username
        attribs = 'mail', "mobile", 'userPrincipalName', \
            'sAMAccountName', "sAMAccountType", \
            "givenName", "sn", "userAccountControl", \
            "memberOf", "primaryGroupID", \
            "whenChanged", "whenCreated", "accountExpires", "pwdLastSet", "lastLogon", \
            "userCertificate", "sshPublicKey", "otherMailbox"
        r = conn.search_s(config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, search_filter, attribs)
        for dn, entry in r:
            if not dn: continue
            user = dict()
            user["created"] = datetime.strptime(entry.get("whenCreated").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")
            user["changed"] = datetime.strptime(entry.get("whenChanged").pop().decode("utf-8"), "%Y%m%d%H%M%S.0Z")
            user["expires"] = ad_time(entry.get("accountExpires").pop())
            user["last_login"] = ad_time(entry.get("lastLogon").pop())
            user["locked"] = bool(int(entry.get("userAccountControl")[0]) & 2)
            user["mail"], = entry.get("mail", (None,))
            user["mobile"], = entry.get("mobile", (None,))
            user["name"], = entry.get("sAMAccountName")
            user["normal"] = bool(int(entry.get("sAMAccountType")[0]) & 0x30000000)
            user["password_set"] = ad_time(entry.get("pwdLastSet").pop())
            user["ssh_keys"] = entry.get("sshPublicKey", ())
            user["certificates"] = [
                serialize_cert(x509.load_der_x509_certificate(j, default_backend()))
                for j in entry.get("userCertificate", ())]

            try:
                user["recovery_mail"], = entry.get("otherMailbox")
            except TypeError:
                # No recovery e-mail configured
                pass

            try:
                user["gn"], = entry.get("givenName")
                user["sn"], = entry.get("sn")
            except TypeError:
                pass

            if user["mail"]:
                user["avatar"] = "https://www.gravatar.com/avatar/%s.jpg?s=32" % hashlib.md5(user["mail"]).hexdigest()

            break
        return user


    @serialize
    @login_required(delegate_credentials=True)
    @ldap_connect
    def on_put(self, req, resp, conn, username):
        ssh_public_keys = [t.encode("ascii") for t in [s.strip() for s in req.get_param("ssh_public_keys", default="").split("\n")] if t]

        gn = req.get_param("gn", required=True)
        sn = req.get_param("sn", default="")
        common_name = " ".join([gn, sn]).strip()

        search_filter = '(&(objectClass=user)(objectCategory=person)(samaccountname=%s))' % username
        attribs = "displayName", "givenName", "sn", "mail", "mobile", "c", "otherMailbox", "userAccountControl", "sshPublicKey"

        for dn, current in conn.search_s(config.LDAP_BASEDN, 2, search_filter, attribs):
            if not dn: continue
            break
        else:
            raise falcon.HTTPNotFound()

        account_control = int(current.get("userAccountControl")[0])

        if req.get_param_as_bool("locked"):
            account_control |= 2
        else:
            account_control &= 0xfffffffd

        if req.get_param_as_bool("password_expires"):
            account_control |= 0x10000
        else:
            account_control &= 0xfffeffff

        attributes = [
            ("displayName", common_name),
            ("givenName", gn),
            ("sn", sn),
            ("mail", req.get_param("mail", default="")),
            ("mobile", req.get_param("mobile", default="")),
            ("c", req.get_param("c", default="")),
            ("otherMailbox", req.get_param("recovery_mail", default="")),
            ("userAccountControl", str(account_control))
        ]

        delta = []

        # Handle strings
        for key, value in attributes:
            old_value = current.get(key)
            new_value = [value.encode("utf-8")]
            if old_value == new_value:
                continue
            if key in current:
                delta += [(1,key,None)]
            if value:
                delta += [(0,key,new_value)]

        # Handle SSH keys
        if set(current.get("sshPublicKey", ())) != set(ssh_public_keys):
            if "sshPublicKey" in current:
                delta += [(1,"sshPublicKey",None)]
            if ssh_public_keys:
                delta += [(0,"sshPublicKey", ssh_public_keys)]

        # Handle password
        if req.get_param("password"):
            delta += [(1,"unicodePwd",None),(0,"unicodePwd",("\"%s\"" % req.get_param("password")).encode("utf-16-le"))]

        if delta:
            try:
                conn.modify_s(dn, delta)
            except ldap.LDAPError as e:
                raise falcon.HTTPBadRequest(e.args[0]["desc"], e.args[0]["info"])
        return {}


    @serialize
    @login_required(delegate_credentials=True)
    @ldap_connect
    def on_delete(self, req, resp, conn, username):
        search_filter = '(&(objectClass=user)(objectCategory=person)(samaccountname=%s))' % username
        r = conn.search_s(config.LDAP_BASEDN, 2, search_filter, [])
        for dn, entry in r:
            if not dn: continue
            try:
                conn.delete_s(dn)
            except ldap.LDAPError as e:
                raise falcon.HTTPBadRequest(e.message.get("info"), e.message.get("desc"))


@apidoc
class UserListResource:
    @serialize
    @login_required(delegate_credentials=True)
    @ldap_connect
    def on_post(self, req, resp, conn):
        req._parse_form_urlencoded() # Merge POST-ed stuff to get_param
        certificates = req.get_param_as_list("certificates") or ()
        username = req.get_param("name", required=True)
        gn = req.get_param("gn", required=True)
        sn = req.get_param("sn")
        common_name = " ".join([gn, sn])
        dn = "cn=%s,cn=Users,%s" % (common_name, config.LDAP_BASEDN)
        upn = "%s@%s" % (username, config.REALM.lower())
        pwd = req.get_param("password")

        # Make sure we're not getting hacked
        RESERVED_GROUPS = set(["root", "audio", "video", "wheel", "sudo", \
            "admin", "daemon", "bin", "lp", "pulse", "lightdm", "dnsmasq", \
            "nobody", "nogroup", "shadow", "kvm", "tape", "floppy", "cdrom", \
            "nslcd", "proxy", "man", "news", "tty", "adm", "disk"])
        if username in RESERVED_GROUPS: # TODO: Use better HTTP status code
            click.echo("Username %s is reserved" % subject_username)
            raise falcon.HTTPConflict("Error", "Username is reserved")
        ldif_user = modlist.addModlist({
            "displayName": common_name.encode("utf-8"),
            "samaccountname": username.encode("utf-8"),
            "givenName": gn.encode("utf-8"),
            "sn": sn.encode("utf-8"),
            "c": req.get_param("c", default="").encode("utf-8"),
            #"birthdate": req.get_param("birthday", default="").encode("utf-8"),
            #"gender": req.get_param("gender", default="").encode("utf-8"),
            "otherMailbox": req.get_param("mail").encode("utf-8"),
            "mail": ("%s@%s" % (username, config.MAIL_DOMAIN)).encode("utf-8"),
            "unicodePwd": ("\"%s\"" % pwd).encode("utf-16-le") if pwd else b"",
            "userAccountControl": b"544",
            "userPrincipalName": upn.encode("utf-8"),
            "objectclass": [b"top", b"person", b"organizationalPerson", b"user"],
            "userCertificate": [b64decode(j) for j in certificates]
                if req.get_param_as_bool("import_certificates") else [],
            #"altSecurityIdentities": TODO
        })

        try:
            conn.add_s(dn, ldif_user)
        except ldap.ALREADY_EXISTS:
            raise falcon.HTTPConflict("Error", "User with such full name already exists")

