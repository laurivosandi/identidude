# encoding: utf-8

import falcon
import ldap
import re
from auth import authenticate, authorize_domain_admin, authorize_owner, generate_password
from forms import validate, RE_PASSWORD
from util import serialize, domain2dn, dn2domain, days_since_epoch
from settings import \
    ADMIN_EMAIL, \
    ADMIN_NAME, \
    LDAP_USER_ATTRIBUTE_USERNAME, \
    LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, \
    LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED

class PasswordResource:
    """
    Password management resource
    """
    def __init__(self, conn, mailer):
        self.conn = conn
        self.mailer = mailer

    @serialize
    @authenticate
    @authorize_domain_admin
    def on_put(self, req, resp, authenticated_user, domain, username):
        """
        Reset password
        """
        if not re.match("[a-z][a-z0-9]{1,31}$", username):
            raise falcon.HTTPBadRequest("Error", "Invalid username")
            
        temporary_password = generate_password(8)
        
        filters = "(&(objectClass=posixAccount)(%s=%s))" % (LDAP_USER_ATTRIBUTE_USERNAME, username)
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, filters, []
        for dn_user, attributes in self.conn.search_s(*args):
            email = attributes.get(LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, [""]).pop()
            break
        else:
            print "No such user: %s" % username
            raise falcon.HTTPNotFound()

        recipients = [ADMIN_EMAIL]
        
        # Send to user himself aswell
        if "@" in email:
            recipients.append(email)
            
        self.mailer.enqueue(
            ADMIN_EMAIL,
            recipients,
            u"Kasutaja %s parool on lähtestatud" % username,
            "email-password-reset",
            username = username,
            password = temporary_password,
            server_helpdesk={"email": ADMIN_EMAIL, "name": ADMIN_NAME}
        )
        
        self.conn.passwd_s(dn_user, None, temporary_password)
        return dict(description="Password successfully reset", recipients=recipients)

    @serialize
    @authenticate
    @authorize_owner
    @validate("password", RE_PASSWORD)
    def on_post(self, req, resp, authenticated_user,  domain, username):
        """
        Set password
        """
        self.conn.passwd_s(authenticated_user.dn.encode("utf-8"), None, req.get_param("password"))
        
        # Update password change timestamp
        ldif = (ldap.MOD_REPLACE, LDAP_USER_ATTRIBUTE_PASSWORD_MODIFIED, str(days_since_epoch())),
        self.conn.modify_s(authenticated_user.dn.encode("utf-8"), ldif)
        
        self.mailer.enqueue(
            ADMIN_EMAIL,
            [authenticated_user.email, ADMIN_EMAIL],
            u"Kasutaja %s parool on muudetud" % username,
            "email-password-changed",
            username = username,
            server_helpdesk={"email": ADMIN_EMAIL, "name": ADMIN_NAME}
        )

    @authenticate
    @authorize_domain_admin
    @serialize
    def on_delete(self, req, resp, authenticated_user, domain, username):
        """
        Lock account
        """
        raise NotImplemented()
        
