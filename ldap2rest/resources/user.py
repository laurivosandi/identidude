# encoding: utf-8

import falcon
import ldap
import os
import random
import re
import string
from auth import authenticate, authorize_domain_admin, generate_password
from ldap import modlist
from datetime import datetime
from forms import validate, required
from util import serialize, domain2dn, dn2domain
from settings import BASE_DOMAIN, HOME, ADMIN_NAME, ADMIN_EMAIL, LDAP_USER_ATTRIBUTE_ID, LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, ADMINS

class UserListResource:
    def __init__(self, conn, mailer=None):
        self.conn = conn
        self.mailer = mailer

    @serialize
    @authenticate
    def on_get(self, req, resp, authenticated_user, domain=BASE_DOMAIN):
        user_fields = "mobile", "gender", "dateOfBirth", "cn", "givenName", \
            "sn", "uid", "uidNumber", "gidNumber", "homeDirectory", \
            "modifyTimestamp", LDAP_USER_ATTRIBUTE_ID,
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, "objectClass=posixAccount", user_fields
        users = dict()
        for dn, attributes in self.conn.search_s(*args):
            m = re.match("cn=(.+?),ou=people,(.+)$", dn)
            cn, dcs = m.groups()
            users[dn] = dict(
                id = attributes.get(LDAP_USER_ATTRIBUTE_ID, [None]).pop(),
                recovery_email = attributes.get(LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, [""]).pop(),
                domain = dn2domain(dcs),
                born = attributes.get("dateOfBirth", [None]).pop(),
                username = attributes.get("uid").pop(),
                uid = int(attributes.get("uidNumber").pop()),
                gid = int(attributes.get("gidNumber").pop()),
                home = attributes.get("homeDirectory").pop(),
                givenName = attributes.get("gn", [""]).pop().decode("utf-8"),
                sn = attributes.get("sn", [""]).pop().decode("utf-8"),
                cn = attributes.get("cn").pop().decode("utf-8"),
                modified = datetime.strptime(attributes.get("modifyTimestamp").pop(), "%Y%m%d%H%M%SZ"))
        return users

    @serialize
    @authenticate
    @authorize_domain_admin
    @required("cn")
    @validate("group",     r"[a-z]{1,32}$", required=False)
    @validate("id",        r"[3-6][0-9][0-9][01][0-9][0-3][0-9][0-9][0-9][0-9][0-9]$", required=False)
    @validate("username",  r"[a-z][a-z0-9]{1,31}$", required=True)
    def on_post(self, req, resp, authenticated_user, domain=BASE_DOMAIN):
        fullname = req.get_param("cn")
        username = req.get_param("username")
        first_name, last_name  = fullname.rsplit(" ", 1)

        home = HOME(username, domain).encode("utf-8")
        initial_password = generate_password(8)
        
        dn_user = "cn=%s,ou=people,%s" % (fullname.encode("utf-8"), domain2dn(domain))
        dn_group = "cn=%s,ou=groups,%s" % (username.encode("utf-8"), domain2dn(domain))
        
        # Make sure we're not getting hacked
        RESERVED_GROUPS = set(["root", "audio", "video", "wheel", "sudo", \
            "admin", "daemon", "bin", "lp", "pulse", "lightdm", "dnsmasq", \
            "nobody", "nogroup", "shadow", "kvm", "tape", "floppy", "cdrom", \
            "nslcd", "proxy", "man", "news", "tty", "adm", "disk"])
        
        if username in RESERVED_GROUPS: # TODO: Use better HTTP status code
            print "Username %s is reserved" % username
            raise falcon.HTTPConflict("Error", "Username is reserved")

        # Search for already existing username
        args = domain2dn(BASE_DOMAIN), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username, []
        for dn, attributes in self.conn.search_s(*args):
            print "Username %s already exists" % username
            raise falcon.HTTPConflict("Error", "Username already exists")
            
        # Automatically assign UID/GID for the user
        UID_MIN = 2000
        UID_MAX = 9000
        args = domain2dn(BASE_DOMAIN), ldap.SCOPE_SUBTREE, "objectClass=posixAccount", ["uidNumber"]
        uids = set()
        for dn, attributes in self.conn.search_s(*args):
            uid = int(attributes["uidNumber"].pop())
            if uid < UID_MIN: continue
            if uid > UID_MAX: continue
            if uid in uids:
                print "Overlapping UID-s for:", dn
            uids.add(uid)
        if uids:
            uid = max(uids) + 1
        else:
            uid = UID_MIN
        if uid > UID_MAX: # TODO: Use better HTTP status code
            raise falcon.HTTPConflict("Error", "Out of UID-s!")
            
        # Extract domain full name
        args = domain2dn(domain), ldap.SCOPE_BASE, "objectClass=domain", ["description"]
        for _, attributes in self.conn.search_s(*args):
            domain_description = attributes.get("description", [domain]).pop().decode("utf-8")

        # Compose list of recipients for the e-mail
        if self.mailer:
            # Add ME!
            recipients = [ADMIN_EMAIL]
            local_helpdesk = None
            
            # Add all local helldesk guys
            for admin_username, subdomain in ADMINS.items():
                if subdomain.endswith("." + domain) or subdomain == domain:
                    args = domain2dn(domain), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % admin_username, [LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, "cn"]
                    for _, attributes in self.conn.search_s(*args):
                        admin_email = attributes.get(LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, [""]).pop()
                        if "@" in admin_email:
                            admin_email = admin_email.replace("@", "+helpdesk@")
                            if domain not in admin_email:
                                admin_email = admin_email.replace("@", "+%s@" % domain)
                            recipients.append(admin_email)
                            local_helpdesk = {"email": admin_email, "name": attributes.get("cn").pop().decode("utf-8")}

            # Add the related user himself
            if req.get_param("email") and req.get_param("notify"):
                recipients.append(req.get_param("email"))
                            
        ldif_user = modlist.addModlist({
            LDAP_USER_ATTRIBUTE_ID: req.get_param("id", "").encode("utf-8") or [],
            LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL: req.get_param("email", "").encode("utf-8"),
            "employeeType": req.get_param("group").encode("utf-8"),
            "uid": username.encode("utf-8"),
            "uidNumber": str(uid),
            "gidNumber": str(uid),
            "sn": last_name.encode("utf-8"),
            "givenName": first_name.encode("utf-8"),
            "mobile": (req.get_param("mobile") or "").encode("utf-8"),
            "preferredLanguage": "en_US",
            "homeDirectory": home,
            "loginShell": "/bin/bash",
            "objectclass": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "shadowAccount", "gosaAccount"]
        })

        ldif_group = modlist.addModlist(dict(
            objectClass = ['top', 'posixGroup'],
            memberUid = [username.encode("utf-8")],
            gidNumber = str(uid),
            cn = username.encode("utf-8"),
            description = ("Group of user %s" % fullname).encode("utf-8")))
            
        ldif_ou_people = modlist.addModlist(dict(
            objectClass = ["organizationalUnit"],
            ou = "people"))
            
        ldif_ou_groups = modlist.addModlist(dict( 
            objectClass = ["organizationalUnit"],
            ou = "groups"))

        try:
            self.conn.add_s("ou=people," + domain2dn(domain), ldif_ou_people)
        except ldap.ALREADY_EXISTS:
            pass
            
        try:
            self.conn.add_s("ou=groups," + domain2dn(domain), ldif_ou_groups)
        except ldap.ALREADY_EXISTS:
            pass

        try:
            self.conn.add_s(dn_user, ldif_user)
        except ldap.ALREADY_EXISTS:
            raise falcon.HTTPConflict("Error", "User with such full name already exists")

        # Set initial password
        self.conn.passwd_s(dn_user, None, initial_password)

        try:
            if not req.get_param("dry"):
                self.conn.add_s(dn_group, ldif_group)
        except ldap.ALREADY_EXISTS:
            raise falcon.HTTPConflict("Error", "Group corresponding to the username already exists")

        if req.get_param("group"):
            ldif = (ldap.MOD_ADD, 'memberUid', username.encode("utf-8")),
            if not req.get_param("dry"):
                try:
                    self.conn.modify_s(("cn=%s,ou=groups,%s" % (req.get_param("group"), domain2dn(BASE_DOMAIN))).encode("utf-8"), ldif)
                except ldap.TYPE_OR_VALUE_EXISTS: # TODO: Remove from group upon user removal
                    pass

        if self.mailer and not req.get_param("batch"): # No e-mailing with batch additions
            self.mailer.enqueue(
                ADMIN_EMAIL,
                recipients,
                u"%s jaoks loodi konto %s" % (fullname, username),
                "email-user-added",
                domain={"description": domain_description},
                username = username,
                password = initial_password,
                local_helpdesk = local_helpdesk,
                server_helpdesk={"email": ADMIN_EMAIL, "name": ADMIN_NAME}
            )
        return dict(
            id = req.get_param("id"),
            domain = domain,
            cn = fullname,
            username = username,
            uid = uid,
            gid = uid,
            initial_password = initial_password,
            first_name = first_name,
            last_name = last_name,
            home = home)

