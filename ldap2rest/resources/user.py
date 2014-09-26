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
from forms import validate, required, \
    RE_USERNAME, \
    RE_CHECKBOX, \
    RE_DATE, \
    RE_EMAIL, \
    RE_PHONE

from util import serialize, domain2dn, dn2domain, apidoc, days_since_epoch
from settings import HOME, ADMIN_NAME, ADMIN_EMAIL, ADMINS, \
    LDAP_BASE_DOMAIN, \
    LDAP_USER_ATTRIBUTE_USERNAME, \
    LDAP_USER_ATTRIBUTE_SURNAME, \
    LDAP_USER_ATTRIBUTE_GIVEN_NAME, \
    LDAP_USER_ATTRIBUTE_MOBILE, \
    LDAP_USER_ATTRIBUTE_LANGUAGE, \
    LDAP_USER_ATTRIBUTE_SHELL, \
    LDAP_USER_ATTRIBUTE_UID, \
    LDAP_USER_ATTRIBUTE_GID, \
    LDAP_USER_ATTRIBUTE_HOME_DIRECTORY, \
    LDAP_USER_ATTRIBUTE_BORN, \
    LDAP_USER_ATTRIBUTE_GENDER, \
    LDAP_USER_ATTRIBUTE_ID, \
    LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, \
    LDAP_USER_ATTRIBUTE_PRIMARY_GROUP, \
    LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED, \
    LDAP_GROUP_ATTRIBUTE_GID, \
    LDAP_GROUP_ATTRIBUTE_MEMBER_USERNAME, \
    LDAP_GROUP_ATTRIBUTE_DESCRIPTION

def decode_id(i):
    if not re.match("\d{11}", i): raise ValueError()
    century = str((int(i[0])-1) / 2 + 18)
    birthday = datetime.strptime(century + i[1:7], "%Y%m%d").date()
    gender = "M" if i[0] in "13579" else "F"
    return gender, birthday

@apidoc
class UserListResource:
    def __init__(self, conn, mailer=None):
        self.conn = conn
        self.mailer = mailer

    @serialize
    @authenticate
    def on_get(self, req, resp, authenticated_user, domain=LDAP_BASE_DOMAIN):
        """
        List users belonging to a particular domain
        """
        user_fields = "cn", "modifyTimestamp", \
            LDAP_USER_ATTRIBUTE_USERNAME, \
            LDAP_USER_ATTRIBUTE_UID, \
            LDAP_USER_ATTRIBUTE_GID, \
            LDAP_USER_ATTRIBUTE_HOME_DIRECTORY, \
            LDAP_USER_ATTRIBUTE_GENDER, \
            LDAP_USER_ATTRIBUTE_BORN, \
            LDAP_USER_ATTRIBUTE_ID, \
            LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, "objectClass=posixAccount", user_fields
        users = dict()
        for dn, attributes in self.conn.search_s(*args):
            m = re.match("cn=(.+?),ou=people,(.+)$", dn)
            cn, dcs = m.groups()
            users[dn] = dict(
                cn = attributes.get("cn").pop().decode("utf-8"),
                id = attributes.get(LDAP_USER_ATTRIBUTE_ID, [None]).pop(),
                recovery_email = attributes.get(LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, [""]).pop(),
                domain = dn2domain(dcs),
                born = attributes.get(LDAP_USER_ATTRIBUTE_BORN, [None]).pop(),
                username = attributes.get(LDAP_USER_ATTRIBUTE_USERNAME).pop(),
                uid = int(attributes.get(LDAP_USER_ATTRIBUTE_UID).pop()),
                gid = int(attributes.get(LDAP_USER_ATTRIBUTE_GID).pop()),
                home = attributes.get(LDAP_USER_ATTRIBUTE_HOME_DIRECTORY).pop(),
                modified = datetime.strptime(attributes.get("modifyTimestamp").pop(), "%Y%m%d%H%M%SZ"))
        return users

    @serialize
    @authenticate
    @authorize_domain_admin
    @validate("group",     r"[a-z]{1,32}$", required=False, help="Primary group")
    @validate("id",        r"[3-6][0-9][0-9][01][0-9][0-3][0-9][0-9][0-9][0-9][0-9]$", required=False, help="National identification number")
    @validate("username",  RE_USERNAME, required=True, help="Username")
    @validate("batch",     RE_CHECKBOX, required=False, help="Batch addition, don't send email notifications to admin")
    @validate("notify",    RE_CHECKBOX, required=False, help="Notify added user via e-mail")
    @validate("cn",        required=False, help="Full name")
    @validate("email",     RE_EMAIL, required=False, help="E-mail address for password recovery")
    @validate("mobile",    RE_PHONE, required=False, help="Mobile phone number")
    def on_post(self, req, resp, authenticated_user, domain=LDAP_BASE_DOMAIN):
        """
        Add user to domain
        """
        subject_fullname = req.get_param("cn")
        subject_username = req.get_param("username")
        subject_first_name, subject_last_name  = subject_fullname.rsplit(" ", 1)
        subject_home = HOME(subject_username, domain).encode("utf-8")
        subject_initial_password = generate_password(8)
        subject_user_dn = "cn=%s,ou=people,%s" % (subject_fullname.encode("utf-8"), domain2dn(domain))
        subject_group_dn = "cn=%s,ou=groups,%s" % (subject_username.encode("utf-8"), domain2dn(domain))
        
        # Extract domain full name
        args = domain2dn(domain), ldap.SCOPE_BASE, "objectClass=domain", ["description"]
        for _, attributes in self.conn.search_s(*args):
            domain_description = attributes.get("description", [domain]).pop().decode("utf-8")

        # Make sure we're not getting hacked
        RESERVED_GROUPS = set(["root", "audio", "video", "wheel", "sudo", \
            "admin", "daemon", "bin", "lp", "pulse", "lightdm", "dnsmasq", \
            "nobody", "nogroup", "shadow", "kvm", "tape", "floppy", "cdrom", \
            "nslcd", "proxy", "man", "news", "tty", "adm", "disk"])
        if subject_username in RESERVED_GROUPS: # TODO: Use better HTTP status code
            print "Username %s is reserved" % subject_username
            raise falcon.HTTPConflict("Error", "Username is reserved")

        # Search for already existing username
        args = domain2dn(LDAP_BASE_DOMAIN), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % subject_username, []
        for dn, attributes in self.conn.search_s(*args):
            print "Username %s already exists" % subject_username
            raise falcon.HTTPConflict("Error", "Username already exists")
            
        # Automatically assign UID/GID for the user
        UID_MIN = 2000
        UID_MAX = 9000
        args = domain2dn(LDAP_BASE_DOMAIN), ldap.SCOPE_SUBTREE, "objectClass=posixAccount", [LDAP_USER_ATTRIBUTE_UID]
        uids = set()
        for dn, attributes in self.conn.search_s(*args):
            subject_uid = int(attributes[LDAP_USER_ATTRIBUTE_UID].pop())
            if subject_uid < UID_MIN: continue
            if subject_uid > UID_MAX: continue
            if subject_uid in uids:
                print "Overlapping UID-s for:", dn
            uids.add(subject_uid)
        if uids:
            subject_uid = max(uids) + 1
        else:
            subject_uid = UID_MIN
        if subject_uid > UID_MAX: # TODO: Use better HTTP status code
            raise falcon.HTTPConflict("Error", "Out of UID-s!")
            
        # Compose list of recipients for the e-mail
        if self.mailer and not req.get_param("batch"):
            # Add ME!
            recipients = [ADMIN_EMAIL]
            local_helpdesk = None
            
            # Add all local helldesk guys
            for username, subdomain in ADMINS.items():
                if domain.endswith("." + subdomain) or subdomain == domain:
                    filters = "(&(objectClass=posixAccount)(%s=%s))" % (LDAP_USER_ATTRIBUTE_USERNAME, username)
                    args = domain2dn(domain), ldap.SCOPE_SUBTREE, filters, [LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, "cn"]
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
                
        try:
            gender, birthday = decode_id(req.get_param("id"))
        except ValueError:
            gender = birthday = ""

        ldif_user = modlist.addModlist({
            LDAP_USER_ATTRIBUTE_ID:                  req.get_param("id").encode("utf-8") or [],
            LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL:      req.get_param("email", "").encode("utf-8"),
            LDAP_USER_ATTRIBUTE_PRIMARY_GROUP:       req.get_param("group").encode("utf-8"),
            LDAP_USER_ATTRIBUTE_USERNAME:            subject_username.encode("utf-8"),
            LDAP_USER_ATTRIBUTE_UID:                 str(subject_uid),
            LDAP_USER_ATTRIBUTE_GID:                 str(subject_uid),
            LDAP_USER_ATTRIBUTE_GENDER:              gender,
            LDAP_USER_ATTRIBUTE_BORN:                birthday.strftime("%Y-%m-%d"),
            LDAP_USER_ATTRIBUTE_SURNAME:             subject_last_name.encode("utf-8"),
            LDAP_USER_ATTRIBUTE_GIVEN_NAME:          subject_first_name.encode("utf-8"),
            LDAP_USER_ATTRIBUTE_MOBILE:              (req.get_param("mobile") or "").encode("utf-8"),
            LDAP_USER_ATTRIBUTE_LANGUAGE:            "en_US",
            LDAP_USER_ATTRIBUTE_HOME_DIRECTORY:      subject_home,
            LDAP_USER_ATTRIBUTE_SHELL:               "/bin/bash",
            LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED:   str(days_since_epoch()),
            "objectclass": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "shadowAccount", "gosaAccount"]
        })

        ldif_group = modlist.addModlist(dict(
            objectClass = ['top', 'posixGroup'],
            memberUid = [username.encode("utf-8")],
            gidNumber = str(subject_uid),
            description = ("Group of user %s" % subject_fullname).encode("utf-8")))
            
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
            self.conn.add_s(subject_user_dn, ldif_user)
        except ldap.ALREADY_EXISTS:
            raise falcon.HTTPConflict("Error", "User with such full name already exists")

        # Set initial password
        self.conn.passwd_s(subject_user_dn, None, subject_initial_password)

        try:
            self.conn.add_s(subject_group_dn, ldif_group)
        except ldap.ALREADY_EXISTS:
            raise falcon.HTTPConflict("Error", "Group corresponding to the username already exists")

        if req.get_param("group"):
            ldif = (ldap.MOD_ADD, LDAP_GROUP_ATTRIBUTE_MEMBER_USERNAME, subject_username.encode("utf-8")),
            try:
                self.conn.modify_s(("cn=%s,ou=groups,%s" % (req.get_param("group"), domain2dn(LDAP_BASE_DOMAIN))).encode("utf-8"), ldif)
            except ldap.TYPE_OR_VALUE_EXISTS: # TODO: Remove from group upon user removal
                pass

        if self.mailer and not req.get_param("batch"): # No e-mailing with batch additions
            self.mailer.enqueue(
                ADMIN_EMAIL,
                recipients,
                u"%s jaoks loodi konto %s" % (subject_fullname, subject_username),
                "email-user-added",
                domain={"description": domain_description},
                username = subject_username,
                password = subject_initial_password,
                local_helpdesk = local_helpdesk,
                server_helpdesk={"email": ADMIN_EMAIL, "name": ADMIN_NAME}
            )
        return dict(
            id = req.get_param("id"),
            domain = domain,
            cn = subject_fullname,
            username = subject_username,
            uid = subject_uid,
            gid = subject_uid,
            initial_password = subject_initial_password,
            first_name = subject_first_name,
            last_name = subject_last_name,
            home = subject_home)

