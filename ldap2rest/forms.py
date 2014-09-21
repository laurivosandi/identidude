
import re
import falcon

RE_CHECKBOX = re.compile(r"(on|yes|1|true)$", re.IGNORECASE) 
RE_USERNAME = re.compile(r"[a-z][a-z0-9]{1,31}$")
RE_PASSWORD = re.compile(r"[A-Za-z0-9@#$%^&+=]{8,}$")
RE_DATE = re.compile(r"\d\d\d\d-\d\d-\d\d$")
RE_PHONE = re.compile(r"\+[0-9]+( [0-9]+)*$")
RE_EMAIL = re.compile(r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-011\013\014\016-\177])*"' # quoted-string
    r')@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?$', re.IGNORECASE)  # dom

def required(*keys):
    def decorate(func):
        def wrapped(instance, req, resp, *args, **kwargs):
            for key in keys:
                if not req.get_param(key):
                    raise falcon.HTTPBadRequest("Error", "No parameter %s specified" % key)
            return func(instance, req, resp, *args, **kwargs)
        wrapped._apidoc = getattr(func, "_apidoc", {})
        wrapped.__doc__ = func.__doc__
        return wrapped
    return decorate
        
def validate(key, regex=None, message=None, required=True, default=u"", help=None):
    if regex:
        if isinstance(regex, str):
            regex = re.compile(regex)
        assert regex.pattern.endswith("$"), "You probably want validator regex to end with $"

    def decorate(func):
        def wrapped(instance, req, resp, *args, **kwargs):
            if key not in req._params:
                req._params[key] = value = default
            value = req._params[key]
            assert isinstance(value, unicode), "Expected unicode for %s, was %s (%s). Are sure you have application/x-www-form-urlencoded; charset=utf-8 for the Content-Type" % (key, repr(value), type(value))
            if not value and required:
                raise falcon.HTTPBadRequest("Error", "No parameter %s specified" % key)
            if value and regex and not regex.match(value):
                raise falcon.HTTPBadRequest("Error", message or "Malformed paramater %s specified" % key)
            return func(instance, req, resp, *args, **kwargs)
        wrapped._apidoc = getattr(func, "_apidoc", {})
        wrapped.__doc__ = func.__doc__
        if not "params" in wrapped._apidoc:
            wrapped._apidoc["params"] = {}
        wrapped._apidoc["params"][key] = {  "required":required, "default":default, "description":help}
        if regex:
            wrapped._apidoc["params"][key]["regex"] = regex.pattern
        if help:
            wrapped._apidoc["params"][key]["description"] = help
        return wrapped
    return decorate
