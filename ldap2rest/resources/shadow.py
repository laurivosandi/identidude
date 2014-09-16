# encoding: utf-8

import falcon
import ldap
import re
import settings
from resources.auth import auth
from forms import validate
from util import serialize, domain2dn, dn2domain, generate_password

class PasswordResource:
    def __init__(self, conn, mailer):
        self.conn = conn
        self.mailer = mailer

    @auth
    @serialize
    def on_put(self, req, resp, domain, username):
        """
        Reset password
        """
        if not re.match("[a-z][a-z0-9]{1,31}$", username):
            raise falcon.HTTPBadRequest("Error", "Invalid username")
            
        temporary_password = generate_password(8)
            
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username, []
        for dn_user, attributes in self.conn.search_s(*args):
            email = attributes.get(settings.LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, [""]).pop()
            break
        else:
            print "No such user: %s" % username
            raise falcon.HTTPNotFound()

        recipients = [settings.ADMIN_EMAIL]
#        if "@" in email:
#            recipients.append(email)
            
        self.mailer.enqueue(
            settings.ADMIN_EMAIL,
            recipients,
            "Teie parool on lähtestatud",
            "email-password-reset",
            username = username,
            password = temporary_password,
            server_helpdesk={"email": settings.ADMIN_EMAIL, "name": settings.ADMIN_NAME}
        )
        
        self.conn.passwd_s(dn_user, None, temporary_password)
        return dict(description="Password successfully reset", recipients=recipients)

    @auth
    @serialize
    @validate("password",  r"[A-Za-z0-9@#$%^&+=]{8,}$")
    @validate("confirm",   r"[A-Za-z0-9@#$%^&+=]{8,}$")
    def on_post(self, req, resp, domain, username):
        """
        Set password
        """
        if not re.match("[a-z][a-z0-9]{1,31}$", username):
            raise falcon.HTTPBadRequest("Error", "Invalid username")
            
        args = domain2dn(domain), ldap.SCOPE_SUBTREE, "(&(objectClass=posixAccount)(uid=%s))" % username, []
        for dn_user, attributes in self.conn.search_s(*args):
            email = attributes.get(settings.LDAP_USER_ATTRIBUTE_RECOVERY_EMAIL, [""]).pop()
            break
        else:
            print "No such user %s" % username
            raise falcon.HTTPNotFound()

    @auth
    @serialize
    def on_delete(self, req, resp, domain, username):
        """
        Lock account
        """
        raise NotImplemented()
        
