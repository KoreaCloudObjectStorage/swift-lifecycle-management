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
        return
    data = json.loads(resp.body)
    if not data:
        return
    for item in data:
        yield item


def make_glacier_hidden_object_name(orig_info, glacier_key):
    keylength = len(glacier_key)
    return '%s-%s-%s' % (keylength, glacier_key, orig_info)


def get_glacier_key_from_hidden_object(hidden_obj):
    keylen = hidden_obj.split('-', 1)[0]
    startpoint = len(keylen)+1
    return hidden_obj[startpoint:int(keylen)+startpoint]


def get_glacier_objname_from_hidden_object(hidden_obj):
    keylen = hidden_obj.split('-', 1)[0]
    startlen = len(keylen)+int(keylen)+2
    return hidden_obj[startlen:]
