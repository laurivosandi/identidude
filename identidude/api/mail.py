# encoding: utf-8

import falcon
import ldap
import os
import random
import re
import string
from datetime import datetime
from identidude.decorators import ldap_connect
from identidude import config

# otherMailbox - ?
# mail - shown in UI
# proxyaddresses - SMTP is the primary one, others are basically aliases. I supposed this could be always overwritten with smtp:userPrincipalName, SMTP:mail
# forwardingAddress - only with exchange schema?

# curl http://id.example.lan/api/aliases > /etc/aliases && newaliases

class MailAliasResource:
    @ldap_connect
    def on_get(self, req, resp, conn):
        attribs = "sAMAccountName", "mail", "userPrincipalName", config.LDAP_RECOVERY_EMAIL
        search_filter = '(&(objectClass=user)(objectCategory=person))'
        r = conn.search_s(config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, search_filter, attribs)
        resp.body = ""
        for dn,entry in r:
            if not dn: continue
            username = entry.get("sAMAccountName").pop().decode("ascii")
            primary_mail = entry.get("mail", [b""]).pop().decode("ascii")
            canonical_address = username + suffix

            upn = entry.get("userPrincipalName", [b""]).pop().decode("ascii")
            aliases = set([])
            if primary_mail and primary_mail != canonical_address:
                if primary_mail.endswith("@" + config.MAIL_DOMAIN): # e-mail address in our domain, create alias for it
                    aliases.add(primary_mail)
                else:
                    aliases.add(canonical_address)

            normalized = [j[:-len(suffix)] if j.endswith(suffix) else j for j in aliases if j]

            if normalized:
                line = "%s: %s" % (username, (" ".join(normalized)))
                resp.body += line + "\n"
