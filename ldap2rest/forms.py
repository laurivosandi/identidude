
import re
import falcon

def required(*keys):
    def decorate(func):
        def wrapped(instance, req, resp, *args, **kwargs):
            for key in keys:
                if not req.get_param(key):
                    raise falcon.HTTPBadRequest("Error", "No parameter %s specified" % key)
            return func(instance, req, resp, *args, **kwargs)
        return wrapped
    return decorate
        
def validate(key, regex, message=None, required=True):
    assert regex.endswith("$"), "You probably want validator regex to end with $"	
    regex = re.compile(regex)
    def decorate(func):
        def wrapped(instance, req, resp, *args, **kwargs):
            value = req.get_param(key) or ""
            assert isinstance(value, unicode), "Parameter %s of invalid type %s, expected unicode" % (key, type(value))
            if not value and required:
                raise falcon.HTTPBadRequest("Error", "No parameter %s specified" % key)
            if value and regex and not regex.match(value):
                raise falcon.HTTPBadRequest("Error", message or "Malformed paramater %s specified" % key)
            return func(instance, req, resp, *args, **kwargs)
        return wrapped
    return decorate
