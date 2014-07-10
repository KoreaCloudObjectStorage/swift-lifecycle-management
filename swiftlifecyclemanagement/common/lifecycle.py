import ast
import calendar
from copy import copy
from datetime import datetime
from operator import itemgetter

from swift.common.http import is_success
from swift.common.swob import Request

# List of Lifecycle Comparison Result
from swift.common.utils import normalize_delete_at_timestamp

LIFECYCLE_OK = 0
LIFECYCLE_ERROR = 1
LIFECYCLE_NOT_EXIST = 2
CONTAINER_LIFECYCLE_IS_UPDATED = 3
CONTAINER_LIFECYCLE_NOT_EXIST = 4
OBJECT_LIFECYCLE_IS_FUTURE = 5
OBJECT_LIFECYCLE_NOT_EXIST = 6
OBJECT_IS_IN_GLACIER = 7

CONTAINER_LIFECYCLE_SYSMETA = 'X-Container-Sysmeta-S3-Lifecycle-Configuration'
GLACIER_FLAG_META = 'X-Object-Meta-Glacier'
LIFECYCLE_RESPONSE_HEADER = 'X-Lifecycle-Response'

OBJECT_LIFECYCLE_META = {
    'id': 'X-Object-Meta-S3-Lifecycle-Configuration-Rule-Id',
    'expire-last': 'X-Object-Meta-S3-Expiration-Last-Modified',
    'transition-last': 'X-Object-Meta-S3-Transition-Last-Modified'
}

DAYS_SECONDS = 86400


class LifecycleCommon(object):
    def __init__(self, account, container, swift_client=None, env=None,
                 app=None):
        self.swift_client = swift_client
        self.env = copy(env)
        self.app = app
        self.headers = None
        self.path = '/v1/%s/%s' % (account, container)

    def _initialize(self):
        resp = None

        if self.swift_client:
            resp = self.swift_client.make_request('HEAD', self.path, {},
                                                  (2, 4))
        elif self.env:
            req = Request(self.env)
            req.method = 'HEAD'
            req.path_info = self.path
            resp = req.get_response(self.app)

        if resp is None:
            return

        self.status = resp.status_int

        if is_success(self.status):
            self.headers = resp.headers


class ContainerLifecycle(LifecycleCommon):
    def __init__(self, account, container, swift_client=None, env=None,
                 app=None):
        LifecycleCommon.__init__(self, account, container,
                                 swift_client=swift_client,
                                 env=env, app=app)
        self._initialize()

    def get_rule_actions_by_object_name(self, prefix):
        rule = self.get_rule_by_object_name(prefix)

        if not rule:
            return None

        rule_info = dict()
        rule_info['ID'] = rule['ID']
        for key in rule:
            if key in ('Expiration', 'Transition'):
                rule_info[key] = rule[key][key.lower() + '-last-modified']

        return rule_info

    def get_rule_by_object_name(self, obj_name):
        lifecycle = self.get_lifecycle()

        if not lifecycle:
            return None

        prefixMap = map(itemgetter('Prefix'), lifecycle)

        prefixIndex = -1
        for p in prefixMap:
            if obj_name.startswith(p):
                prefixIndex = prefixMap.index(p)
                break

        if prefixIndex < 0:
            return None

        rule = lifecycle[prefixIndex]
        return rule

    def get_lifecycle(self):
        if not self.headers or \
                        CONTAINER_LIFECYCLE_SYSMETA not in self.headers:
            return None

        return ast.literal_eval(self.headers[CONTAINER_LIFECYCLE_SYSMETA])

    def reload(self):
        self._initialize()


class ObjectLifecycle(LifecycleCommon):
    def __init__(self, account, container, obj, swift_client=None,
                 env=None, app=None):
        LifecycleCommon.__init__(self, account, container,
                                 swift_client=swift_client,
                                 env=env, app=app)
        self.path = '/v1/%s/%s/%s' % (account, container, obj)
        self.obj_name = obj;
        self._initialize()

    def get_rule_actions(self):
        if not self.headers or \
                        OBJECT_LIFECYCLE_META['id'] not in self.headers:
            return None

        lifecycle = dict()
        lifecycle['ID'] = self.headers[OBJECT_LIFECYCLE_META['id']]
        for key, value in self.headers.iteritems():
            if key in (OBJECT_LIFECYCLE_META['expire-last'],
                       OBJECT_LIFECYCLE_META['transition-last']):
                lifecycle[key.split('-', 5)[4]] = value
        return lifecycle

    def get_s3_storage_class(self):
        if not self.headers:
            return None

        if GLACIER_FLAG_META in self.headers:
            return 'GLACIER'
        return 'STANDARD'

    def reload(self):
        self._initialize()


class Lifecycle(object):
    def __init__(self, account, container, obj, swift_client=None,
                 env=None, app=None):
        self.swift_client = swift_client
        self.env = env
        self.app = app
        self.object = ObjectLifecycle(account, container, obj, env=env,
                                      app=app, swift_client=swift_client)
        self.container = ContainerLifecycle(account, container, env=env,
                                            app=app,
                                            swift_client=swift_client)

    def get_s3_storage_class(self):
        return self.object.get_s3_storage_class()

    def get_object_lifecycle(self):
        lifecycle = self.container.get_lifecycle()

        object_meta = self.object.get_rule_actions()

        if not lifecycle or not object_meta:
            return None

        rule_id = object_meta['ID']
        rule_id_map = map(itemgetter('ID'), lifecycle)

        if rule_id not in rule_id_map:
            return None

        return lifecycle[rule_id_map.index(id)]

    def object_lifecycle_validation(self):
        obj_name = self.object.obj_name
        c_rule = self.container.get_rule_actions_by_object_name(obj_name)
        o_rule = self.object.get_rule_actions()

        if c_rule:
            if o_rule:
                if c_rule == o_rule:
                    return LIFECYCLE_OK

                for key in ('Expiration', 'Transition'):
                    if (key not in c_rule and
                                key in o_rule) or \
                            (key in c_rule and
                                     key not in o_rule):
                        return CONTAINER_LIFECYCLE_IS_UPDATED

                    elif key not in c_rule and key not in o_rule:
                        continue

                    if c_rule[key] == o_rule[key]:
                        continue
                    elif c_rule[key] > o_rule[key]:
                        return CONTAINER_LIFECYCLE_IS_UPDATED
                    elif c_rule[key] < o_rule[key]:
                        return LIFECYCLE_ERROR
            else:
                return OBJECT_LIFECYCLE_NOT_EXIST
        else:
            if o_rule:
                return CONTAINER_LIFECYCLE_NOT_EXIST
            else:
                return LIFECYCLE_NOT_EXIST

    def reload(self):
        self.object.reload()
        self.container.reload()


def calc_when_actions_do(rule, from_time):
    timelist = dict()

    for key in ('Expiration', 'Transition'):
        if key not in rule:
            continue
        action = rule[key]
        time = None
        if 'Date' in action:
            time = calendar.timegm(datetime.strptime(action['Date'],
                                                     '%Y-%m-%dT%H:%M:%S+00:00')
                                   .timetuple())
        elif 'Days' in action:
            time = calc_nextDay(from_time) + int(action['Days']) * DAYS_SECONDS
            time = normalize_delete_at_timestamp(time)
        timelist[key] = time
    return timelist


def calc_nextDay(timestamp):
    current = normalize_delete_at_timestamp((int(timestamp) / DAYS_SECONDS) *
                                            DAYS_SECONDS)
    return int(current) + DAYS_SECONDS