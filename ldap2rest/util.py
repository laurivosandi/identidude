
import falcon
import json
import re
import unicodedata
import urlparse
from datetime import datetime

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
            if re.match("application/x-www-form-urlencoded(; *charset=utf-8)?$", req.get_header("content-type"), re.I):
                for key, value in urlparse.parse_qs(buf).items():
                    req._params[key] = value[0].decode("utf-8")
            else:
                raise falcon.HTTPError(falcon.HTTP_400,
                    "Unknown content type",
                    "Could not understand content type %s of the body of the request" % req.get_header("content-type"))

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
    

