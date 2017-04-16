import falcon
import ldap
import ldap.sasl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from identidude.decorators import serialize, apidoc, ldap_connect
from cryptography.hazmat.primitives.serialization import Encoding
from identidude.decorators import login_required
from identidude import config

# curl http://id.example.lan/api/user.pem
# pkcs15-tool -r 1 > esteid.pem
# curl -u : --negotiate --delegation always --data-binary @esteid.pem http://id.example.lan/api/user.pem

@apidoc
class CertificateResource(object):
    @ldap_connect
    def on_get(self, req, resp, conn, username):
        """
        Fetch the first X509 certificate stored in userCertificate attribute
        """
        flt = "(&(objectClass=person)(samaccountname=%s))" % username
        attrs = "userCertificate",
        args = config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, flt, attrs

        for dn, entry in conn.search_s(*args):
            if not dn:
                continue
            der_buf = entry.get("userCertificate", ([None])).pop() # TODO: retrieve other certs
            if not der_buf:
                continue
            cert = x509.load_der_x509_certificate(der_buf, default_backend())
            resp.body = cert.public_bytes(Encoding.PEM)
            break
        else:
            raise falcon.HTTPNotFound()


    @login_required(delegate_credentials=True)
    @ldap_connect
    def on_post(self, req, resp, conn, username):
        """
        Upload certificate in PEM form and store it in userCertificate attribute
        """
        buf = req.stream.read()
        cert = x509.load_pem_x509_certificate(buf, default_backend())
        cert_buf = cert.public_bytes(Encoding.DER)
        flt = "(samaccountname=%s)" % username
        attrs = "userCertificate",
        args = config.LDAP_BASEDN, ldap.SCOPE_SUBTREE, flt, attrs

        for dn, entry in conn.search_s(*args):
            if not dn:
                continue
            existing_certs = entry.get("userCertificate", ())
            if cert_buf in existing_certs:
                break

            if existing_certs:
                attribute = (ldap.MOD_REPLACE, "userCertificate", [cert_buf] + existing_certs)
            else:
                attribute = (ldap.MOD_ADD, "userCertificate", [cert_buf])
            conn.modify_s(dn, [attribute])
