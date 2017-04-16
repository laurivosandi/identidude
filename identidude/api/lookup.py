import falcon
import ldap
import re
import textwrap
import unicodedata
from base64 import b64encode
from datetime import datetime
from time import sleep
from identidude.decorators import serialize, chunks
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID

class LookupResource:
    def __init__(self):
        self.conn = ldap.initialize("ldap://ldap.sk.ee", bytes_mode=False)

    def get_certificates(self, codes):
        for chunk in chunks(tuple(codes), 50):
            query = "".join(["(serialNumber=%s)" % j for j in chunk])
            if len(chunk) > 1:
                query = "(|" + query  + ")"
            esteid = dict()
            digiid= dict()
            args = "ou=Authentication,o=ESTEID,c=EE", ldap.SCOPE_SUBTREE, query, ["serialNumber", "userCertificate;binary"]
            for dn, attributes in self.conn.search_s(*args):
                serial = attributes["serialNumber"].pop().decode("utf-8")
                esteid[serial], = attributes["userCertificate;binary"]
            args = "ou=Authentication,o=ESTEID (DIGI-ID),c=EE", ldap.SCOPE_SUBTREE, query, ["serialNumber", "userCertificate;binary"]
            for dn, attributes in self.conn.search_s(*args):
                serial = attributes["serialNumber"].pop().decode("utf-8")
                digiid[serial], = attributes["userCertificate;binary"]
            for code in chunk:
                yield code, esteid.get(code, None), digiid.get(code, None)


    @serialize
    def on_get(self, req, resp):
        ids = req.get_param("ids")
        if isinstance(ids, str):
            ids = ids.split(",")

        codes = set([j for j in ids if re.match("[3-6]\d{10}", j)])

        if not codes:
            raise falcon.HTTPBadRequest("No id codes specified")

        users = dict()
        for serial, esteid, digiid in self.get_certificates(ids):
            cert = x509.load_der_x509_certificate(esteid, default_backend())
            common_name, = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            given_name, = cert.subject.get_attributes_for_oid(NameOID.GIVEN_NAME)
            surname, = cert.subject.get_attributes_for_oid(NameOID.SURNAME)
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            mail, = ext.value.get_values_for_type(x509.RFC822Name)
            slug = (given_name.value[0] + surname.value).replace("-", "").replace(" ", "")
            username = unicodedata.normalize("NFKD", slug.lower()).encode("ascii", "ignore")
            century = str((int(serial[0])-1) // 2 + 18)
            users[serial] = dict(
                gender="M" if serial[0] in "13579" else "F",
                birthday = datetime.strptime(century + serial[1:7], "%Y%m%d").date(),
                cn=common_name.value,
                gn=given_name.value.title(),
                sn=surname.value.title(),
                mail=mail,
                name=username,
                certificates = [b64encode(j) for j in (esteid,digiid) if j],
            )
        return users
