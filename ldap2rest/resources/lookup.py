import base64
import ldap
import re
import textwrap
from M2Crypto import X509
from settings import PEM_PATH
from time import sleep
from util import serialize, chunks

class LookupResource:
    def __init__(self):
        self.conn = ldap.initialize("ldap://ldap.sk.ee")

    @serialize
    def on_get(self, req, resp):
        codes = set([j for j in req.get_param("ids").split(",") if re.match("[3-6]\d{10}", j)])

        if not codes:
            raise falcon.HTTPBadRequest("No id codes specified")

        certs = dict()
        
        # Read certificates from cache
        for code in codes:
            try:
                with open(PEM_PATH % code) as fh:
                    certs[code] = fh.read()
            except IOError:
                pass

        # Don't download certs found from cache
        for code in certs:
            codes.remove(code)

        # Chunk queries to 50 items each
        for chunk in chunks(tuple(codes), 50):
            query = "".join(["(serialNumber=%s)" % j for j in chunk])
            if len(chunk) > 1:
                query = "(|" + query  + ")"
            args = "ou=Authentication,o=ESTEID,c=EE", ldap.SCOPE_SUBTREE, query, ["serialNumber", "userCertificate;binary"]
            for dn, attributes in self.conn.search_s(*args):
                pem = ["-----BEGIN CERTIFICATE-----"]
                for line in textwrap.wrap(base64.b64encode(attributes["userCertificate;binary"].pop()), 64):
                    pem.append(line)
                pem.append("-----END CERTIFICATE-----")
                serialNumber = attributes["serialNumber"].pop()
                pem = "\n".join(pem)
                with open(PEM_PATH % serialNumber, "w") as fh:
                    fh.write(pem)
                certs[serialNumber] = pem
                codes.remove(serialNumber)
            sleep(1)

        # Touch not found ones
        for serialNumber in codes:
            with open(PEM_PATH % serialNumber, "w") as fh:
                pass

        users = dict()                    
        for serialNumber, pem in certs.items():
            if not certs[serialNumber]:
                continue

            cert = X509.load_cert_string(certs[serialNumber])
            subject = cert.get_subject()
            user = dict()
            
            for key in "SN", "GN":
                try:
                    user[key.lower()] = getattr(subject, key).decode('string-escape').decode("utf-8")
                except UnicodeDecodeError:
                    user[key.lower()] = getattr(subject, key).decode('string-escape').decode("utf-16-be")

            user["sn"] = user["sn"].title()
            user["gn"] = user["gn"].title()
            user["email"] = cert.get_ext('subjectAltName').get_value().split(":")[1]
            users[serialNumber] = user
        return users

