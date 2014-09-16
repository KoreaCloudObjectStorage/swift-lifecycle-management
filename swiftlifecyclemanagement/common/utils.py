import calendar
import json
from datetime import datetime


def gmt_to_timestamp(gmt_time):
    # convert object's last_modified(UTC TIME) to Unix Timestamp
    timestamp = datetime.strptime(gmt_time,
                                  '%a, %d %b %Y %H:%M:%S GMT')
    timestamp = calendar.timegm(timestamp.utctimetuple())
    return timestamp


def get_objects_by_prefix(account, container, prefix, swift_client):
    iter_objs = iter_objects_by_prefix(account, container, prefix,
                                       swift_client)
    objs = list()
    for o in iter_objs:
        objs.append(o['name'])
    return objs


def iter_objects_by_prefix(account, container, prefix, swift_client):
    path = swift_client.make_path(account, container)
    param = 'format=json&prefix=%s' % prefix
    resp = swift_client.make_request('GET', '%s?%s' % (path, param), {},
                                     (2, 4))
    if not resp.status_int == 200:
        break
    data = json.loads(resp.body)
    if not data:
        break
    for item in data:
        yield item