# encoding: utf-8
import falcon
import json
import re
import unicodedata
import urlparse
from datetime import datetime, date

def apidoc(cls):
    """
    Automagically document resource classes based on validate(), required(), etc decorators
    """
    @serialize
    def apidoc_on_options(resource, req, resp, *args, **kwargs):
        d = {}
        for key in dir(resource):
            if key == "on_options": continue
            if re.match("on_\w+", key):
                func = getattr(resource, key)
                d[key[3:]] = getattr(func, "_apidoc", None)
                d[key[3:]]["description"] = (getattr(func, "__doc__") or u"").strip()
                
        return d
    cls.on_options = apidoc_on_options
    return cls

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
        if isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        return json.JSONEncoder.default(self, obj)

def serialize(func):
    """
    Falcon response serialization
    """
    def wrapped(instance, req, resp, **kwargs):
        assert req.get_param("unicode") == u"✓", "Unicode sanity check failed"
        
        # Default to no caching of API calls
        resp.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        resp.set_header("Pragma", "no-cache");
        resp.set_header("Expires", "0");

        r = func(instance, req, resp, **kwargs)

        if not resp.body:
            if not req.client_accepts_json:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports the JSON media type.',
                    href='http://docs.examples.com/api/json')
            resp.set_header('Content-Type', 'application/json')
            resp.body = json.dumps(r, encoding="utf-8", cls=MyEncoder)
        return r
        
    # Pipe API docs
    wrapped._apidoc = getattr(func, "_apidoc", {})
    wrapped.__doc__ = func.__doc__
    return wrapped
    
def days_since_epoch(today=None):
    if not today:
        today = date.today()
    return (today - date(1970,1,1)).days

