# encoding: utf-8
import base64
import click
import falcon
import gssapi
import json
import logging
import os
import re
import socket
import unicodedata
from identidude import config
from datetime import datetime, date

logger = logging.getLogger(__name__)

# http://firstyear.id.au/blog/html/2015/11/26/python_gssapi_with_flask_and_s4u2proxy.html
os.environ["KRB5_KTNAME"] = "FILE:/etc/identidude/server.keytab"
server_creds = gssapi.creds.Credentials(
    usage='accept',
    name=gssapi.names.Name('HTTP/%s'% (socket.gethostname())))

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


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode("utf-8")
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
        assert not req.get_param("unicode") or req.get_param("unicode") == u"✓", "Unicode sanity check failed"

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
            resp.body = json.dumps(r, cls=MyEncoder)
        return r

    # Pipe API docs
    wrapped._apidoc = getattr(func, "_apidoc", {})
    wrapped.__doc__ = func.__doc__
    return wrapped

def ldap_connect(func):
    import ldap, ldap.sasl
    def wrapped(resource, req, resp, *args, **kwargs):
        conn = ldap.initialize(config.LDAP_URI)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.sasl_interactive_bind_s('', ldap.sasl.gssapi())
        retval = func(resource, req, resp, conn, *args, **kwargs)
        conn.unbind_s()
        return retval
    return wrapped

def login_required(delegate_credentials=False):
    def wrapper(func):
        def kerberos_authenticate(resource, req, resp, *args, **kwargs):
            if not req.auth:
                logger.debug(u"No Kerberos ticket offered while attempting to access %s from %s",
                    req.env["PATH_INFO"], req.context.get("remote_addr"))
                raise falcon.HTTPUnauthorized("Unauthorized",
                    "No Kerberos ticket offered, are you sure you've logged in with domain user account?",
                    ["Negotiate"])


            context = gssapi.sec_contexts.SecurityContext(creds=server_creds)
            token = ''.join(req.auth.split()[1:])
            context.step(base64.b64decode(token))

            if delegate_credentials:
                if not context.delegated_creds:
                    logger.debug(u"No credentials delegated for %s from %s",
                        req.env["PATH_INFO"], req.context.get("remote_addr"))
                    raise falcon.HTTPForbidden("Error", "No credential delegation enabled")
                CCACHE = 'MEMORY:ccache_rest389_%s' % context.delegated_creds.name
                store = {'ccache': CCACHE}
                context.delegated_creds.store(store, overwrite=True)
                os.environ['KRB5CCNAME'] = CCACHE # This will definitely break multithreading
            req.context["user"], req.context["realm"] = repr(context.initiator_name).split("@")
            req.context["remote_addr"] = "bla"
            retval = func(resource, req, resp, *args, **kwargs)
            del(os.environ['KRB5CCNAME'])
            return retval
        return kerberos_authenticate
    return wrapper
