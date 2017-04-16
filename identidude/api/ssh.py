import os
import ldap
import struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from identidude.decorators import login_required, serialize, apidoc, ldap_connect
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID, ExtensionOID
from identidude import config

# https://www.balabit.com/documents/scb-latest-guides/en/scb-guide-admin/html/proc-scenario-usermapping.html
# Following works on Samba4, note that attribute wont be user-editable via ADUC easiy, needs some tweaking
# https://gist.github.com/hsw0/5132d5dabd4384108b48

# kinit user@EXAMPLE.LAN
# curl -u : --negotiate --delegation always --data-binary @$HOME/.ssh/authorized_keys http://id.example.lan/api/$USER.keys
# curl http://id.example.lan/api/user.keys?x509=on

class AuthorizedKeysResource:
    @ldap_connect
    def on_get(self, req, resp, conn, samaccountname):
        """
        Retrieve SSH keys corresponding to users
        """
        resp.body = ""
        samaccountname = samaccountname.lower().replace("_", " ")
        attribs = "sshPublicKey", "userCertificate", "objectClass", "sAMAccountName", "objectSid"
        query = "(samaccountname=%s)" % samaccountname
        args = config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, query, attribs
        result = conn.search_s(*args)
        for dn, entry in result:
            if not dn:
                continue
            if b"group" in entry.get("objectClass"):
                # This is group, need to look up individual users below
                sid, = entry.get("objectSid")
                rid, = struct.unpack("i", sid[-4:])
                query = "(|(primaryGroupID=%s)(memberOf=%s))" % (rid, dn)
                attribs = "sshPublicKey", "sAMAccountName", "userCertificate",
                args = config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, query, attribs
                result = conn.search_s(*args)
            break

        for dn, entry in result:
            if not dn:
                continue
            username = entry.get("sAMAccountName").pop().decode("utf-8")

            # Include sshPublicKey attribute contents
            for key in entry.get("sshPublicKey", []):
                resp.body += "%s (%s)\n" % (key.decode("utf-8"), username)

            # Include X509 certificates as SSH public keys
            if req.get_param_as_bool("x509"):
                for der_buf in entry.get("userCertificate") or ():
                    cert = x509.load_der_x509_certificate(der_buf, default_backend())
                    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

                    c, = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
                    o, = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    ou, = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
                    cn, = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

                    comment = ",".join([j.value for j in (c,o,ou,cn) if j])

                    mail, = ext.value.get_values_for_type(x509.RFC822Name)
                    resp.body += "%s %s\n" % (
                        cert.public_key().public_bytes(
                            Encoding.OpenSSH,
                            serialization.PublicFormat.OpenSSH).decode("ascii"),
                        comment)


    @login_required(delegate_credentials=True)
    @ldap_connect
    def on_post(self, req, resp, conn, samaccountname):
        new_keys = set([j for j in req.stream.read().decode("ascii").split("\n") if j])
        # TODO: sanitize input, compare actual public keys, not with comment
        flt = "(&(objectClass=person)(samaccountname=%s))" % samaccountname
        attrs = "sshPublicKey",
        args = config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, flt, attrs

        for dn, entry in conn.search_s(*args):
            if not dn:
                continue
            existing_keys = set([j.decode("ascii") for j in entry.get("sshPublicKey", ())])
            if existing_keys:
                attribute = (ldap.MOD_REPLACE, "sshPublicKey", [j.encode("ascii") for j in existing_keys.union(new_keys)])
            else:
                attribute = (ldap.MOD_ADD, "sshPublicKey", [j.encode("ascii") for j in new_keys])
            conn.modify_s(dn, [attribute])
