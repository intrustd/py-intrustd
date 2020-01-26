import requests
from urllib.parse import urljoin

def get_appliance_identity(app_endpoint='http://admin.intrustd.com.app.local'):
    from werkzeug.exceptions import Unauthorized

    r = requests.get(urljoin(app_endpoint, '/appliance/identity'))

    if r.status_code == 200:
        return r.json()
    elif r.status_code == 404:
        raise NotImplemented()
    elif r.status_code == 403:
        raise Unauthorized()
    else:
        raise RuntimeError("Unknown status code while attempting to get public key: {}".format(r.status_code))
