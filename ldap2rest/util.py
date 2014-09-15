
import falcon
import hashlib
import json
import random
import re
import unicodedata
import urlparse
from datetime import datetime
from settings import COOKIE_SECRET

def generate_password(length):
    return ''.join(random.sample("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789", length))

def normalize_username(first, last, serialNumber):
    username = first[0] + last + serialNumber[-4:]
    username = username.replace("-", "")
    username = username.replace(" ", "")
    username = unicodedata.normalize("NFKD", (username).lower()).encode("ascii", "ignore").decode("ascii")
    return username
    
def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]
        
def domain2dn(domain):
    assert re.match("[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$", domain), "Invalid domain name '%s'" % domain
    return ",".join(["dc=" + dc for dc in domain.split(".")])

def dn2domain(dn):
    assert re.match("dc=[a-z0-9]+(-[a-z0-9]+)*(\,dc=[a-z0-9]+(-[a-z0-9]+)*)+$", dn)
    return ".".join([dc[3:] for dc in dn.split(",")])

def generate_token(username, created):
    created = created.strftime("%s")
    digest = hashlib.sha1()
    digest.update(username)
    digest.update("|")
    digest.update(created)
    digest.update("|")
    digest.update(COOKIE_SECRET)
    return "%s,%s,%s" % (username, created, digest.hexdigest())
    
class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "Z"
        return json.JSONEncoder.default(self, obj)

def serialize(func):
    """
    Falcon request/response serialization
    """
    def wrapped(instance, req, resp, **kwargs):
        if req.content_length:
            buf = req.stream.read(req.content_length)
            if req.get_header("content-type") == "application/x-www-form-urlencoded":
                for key, value in urlparse.parse_qs(buf).items():
                    req._params[key] = value[0]
            elif req.get_header("content-type") == "application/json":
                try:
                    body = json.loads(buf, encoding='utf-8')
                except ValueError:
                    raise falcon.HTTPError(falcon.HTTP_400,
                        "Malformed JSON",
                        "Could not decode the request body. The JSON was incorrect.")
                else:
                    for key, value in body.items():
                        req._params[key] = value
            else:
                raise falcon.HTTPError(falcon.HTTP_400,
                    "Unknown content type",
                    "Could not understand content type ",
                    req.get_header("content-type"),
                    "of the body of the request")

        r = func(instance, req, resp, **kwargs)
        if not resp.body:
            if not req.client_accepts_json:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports the JSON media type.',
                    href='http://docs.examples.com/api/json')
            resp.set_header('Access-Control-Allow-Origin', '*')
            resp.set_header('Content-Type', 'application/json')
            resp.body = json.dumps(r, encoding="utf-8", cls=MyEncoder)
        return r
    return wrapped
    

