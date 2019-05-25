from urllib.parse import urljoin
from datetime import datetime

import os
import requests

def schedule_command(cmd, data=None,
                     endpoint=os.getenv('INTRUSTD_ADMIN_ENDPOINT', 'http://admin.intrustd.com.app.local'),
                     run_after=None, retain_until=None, alias=None):
    d = { 'command': cmd }
    if run_after is not None:
        if not isinstance(run_after, datetime):
            raise TypeError('run_after should be of type datetime')
        d['run_after'] = datetime_json(run_after)

    if retain_until is not None:
        if not isinstance(retain_until, datetime):
            raise TypeError('retain_until should be of type datetime')
        d['retain_until'] = datetime_json(retain_until)

    if alias is not None:
        d['alias'] = alias

    r = requests.post(urljoin(endpoint, '/schedule'), json=d)
    if r.status_code == 201:
        rsp = r.json()
        return rsp
    elif r.status_code == 409:
        raise KeyError(alias)
    else:
        raise RuntimeError('Unknown status code while adding command: {} {}'.format(r.status_code, r.text))

def get_scheduled_command_status(task_id,
                                 endpoint=os.getenv('INTRUSTD_ADMIN_ENDPOINT', 'http://admin.intrustd.com.app.local')):
    r = requests.get(urljoin(endpoint, '/schedule/{}'.format(task_id)))
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 404:
        raise KeyError(task_id)
    else:
        raise RuntimeError('Unknown status while checking command status: {}'.format(r.status_code))
