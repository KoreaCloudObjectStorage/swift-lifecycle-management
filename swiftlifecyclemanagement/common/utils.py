import calendar
import json
from datetime import datetime
from swift.common.wsgi import make_pre_authed_env, make_pre_authed_request
from swift import gettext_ as _


def gmt_to_timestamp(gmt_time):
    # convert object's last_modified(UTC TIME) to Unix Timestamp
    timestamp = datetime.strptime(gmt_time,
                                  '%a, %d %b %Y %H:%M:%S GMT')
    timestamp = calendar.timegm(timestamp.utctimetuple())
    return timestamp


def get_objects_by_prefix(account, container, prefix, swift_client=None,
                          app=None):
    iter_objs = iter_objects_by_prefix(account, container, prefix,
                                       swift_client, app)
    objs = list()
    for o in iter_objs:
        objs.append(o['name'])
    return objs


def iter_objects_by_prefix(account, container, prefix, swift_client=None,
                           app=None):
    marker = ''
    while True:
        param = 'format=json&marker=%s' % marker
        if marker == '':
            param = '%s&prefix=%s' % (param, prefix)

        if swift_client:
            path = swift_client.make_path(account, container)
            resp = swift_client.make_request('GET', '%s?%s' % (path, param),
                                             {}, (2, 4))
        elif app:
            path = '/v1/%s/%s' % (account, container)
            env = make_pre_authed_env({}, method='GET', path=path,
                                      query_string=param)
            req = make_pre_authed_request(env)
            resp = req.get_response(app)

        if not resp.status_int == 200:
            break

        data = json.loads(resp.body)
        if not data:
            break
        for item in data:
            yield item
        marker = data[-1]['name'].encode('utf8')


def make_glacier_hidden_object_name(orig_info, glacier_key):
    keylength = len(glacier_key)
    return '%s/%s/%s' % (orig_info, glacier_key, keylength)


def get_glacier_key_from_hidden_object(hidden_obj):
    keylenstr = hidden_obj.split('/')[-1]
    keylen = int(keylenstr)
    startpoint = len(hidden_obj) -  (keylen + len(keylenstr) + 1)
    return hidden_obj[startpoint: startpoint+keylen]


def get_glacier_objname_from_hidden_object(hidden_obj):
    keylenstr = hidden_obj.split('/')[-1]
    keylen = int(keylenstr)
    endpoint = len(hidden_obj) - (keylen + len(keylenstr) + 2)
    return hidden_obj[:endpoint]


def report_exception(logger=None, msg=None, reporter=None):
    if logger is not None and msg is not None:
        logger.exception(_(msg))
    if reporter is not None:
        reporter.captureException()