import calendar
import time
import dateutil.parser
import json
from copy import copy
from operator import itemgetter
from hashlib import md5

from swift.common.http import is_success
from swift.common.swob import Request
from swift.common.wsgi import make_pre_authed_request
from swift.common.ring import Ring

# List of Lifecycle Comparison Result
from swift.common.utils import normalize_delete_at_timestamp, \
    normalize_timestamp
from swift.common.bufferedhttp import http_connect

LIFECYCLE_OK = 0
LIFECYCLE_ERROR = 1
LIFECYCLE_NOT_EXIST = 2
CONTAINER_LIFECYCLE_IS_UPDATED = 3
CONTAINER_LIFECYCLE_NOT_EXIST = 4
OBJECT_LIFECYCLE_NOT_EXIST = 5
SKIP_THIS_OBJECT = 7
DISABLED_EXPIRATION = 8
DISABLED_TRANSITION = 9
DISABLED_BOTH = 10

GLACIER_FLAG_META = 'X-Object-Meta-Glacier'
LIFECYCLE_RESPONSE_HEADER = 'X-Lifecycle-Response'

OBJECT_LIFECYCLE_META = {
    'Expiration': 'X-Object-Meta-S3-Expiration-',
    'Transition': 'X-Object-Meta-S3-Transition-'
}

DAY_SECONDS = 86400


class LifecycleCommon(object):
    def __init__(self, account, container, swift_client=None, env=None,
                 app=None):
        self.swift_client = swift_client
        self.env = copy(env)
        self.app = app
        self.headers = None
        self.status = None
        self.account = account
        self.container = container
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
            req.headers['Content-Length'] = '0'
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
        rules = self.get_rules_by_object_name(prefix)

        rule_info = dict()
        for rule in rules:
            for key in rule:
                if key in ('Expiration', 'Transition'):
                    rule_info[key + '-Id'] = rule['ID']
                    rule_info[key] = rule[key]['LastModified']
                    rule_info[key + '-Status'] = rule['Status']
        return rule_info

    def get_rules_by_object_name(self, obj_name):
        lifecycle = self.get_lifecycle()

        if not lifecycle:
            return []

        sortedlist = sorted(lifecycle, key=lambda k: k['Prefix'])
        prefixMap = map(itemgetter('Prefix'), sortedlist)
        rules = list()
        for p in prefixMap:
            if p > obj_name:
                break

            # The maximum number of rules for object are two,
            # so if rules length is 2, escape for loop.
            if len(rules) == 2:
                break

            if obj_name.startswith(p):
                prefixIndex = prefixMap.index(p)
                rule = sortedlist[prefixIndex]
                rules.append(rule)

        if len(rules) == 0:
            return []

        return rules

    def get_lifecycle(self):

        path = '/v1/.s3_bucket_lifecycle/%s/%s' % (self.account,
                                                   self.container)

        if self.swift_client:
            resp = self.swift_client.make_request('GET', path, {}, {2})
        else:
            req = make_pre_authed_request(self.env, 'GET', path=path,
                                          agent='lifecycle-middleware')
            req.environ['swift.proxy_access_log_made'] = True
            resp = req.get_response(self.app)

        if resp.status_int == 404:
            return None

        lc_raw = resp.body

        return json.loads(lc_raw)

    def set_lifecycle(self, lifecycle):
        lifecycle = json.dumps(lifecycle)
        return self._delete_or_save_lifecycle('PUT', lifecycle)

    def delete_lifecycle(self):
        self._delete_or_save_lifecycle('DELETE')

    def _delete_or_save_lifecycle(self, method, lifecycle=None):
        path = '/.s3_bucket_lifecycle/%s/%s' % (self.account, self.container)
        oring = Ring('/etc/swift', ring_name='object')
        cring = Ring('/etc/swift', ring_name='container')
        part, nodes = oring.get_nodes('.s3_bucket_lifecycle', self.account,
                                      self.container)
        cpart, cnodes = cring.get_nodes('.s3_bucket_lifecycle', self.account)
        now_ts = normalize_timestamp(time.time())

        i = 0
        for node in nodes:
            ip = node['ip']
            port = node['port']
            dev = node['device']
            headers = dict()
            headers['user-agent'] = 'lifecycle-uploader'
            headers['X-Timestamp'] = now_ts
            headers['referer'] = 'lifecycle-uploader'
            headers['X-Container-Partition'] = cpart
            headers['X-Container-Host'] = '%(ip)s:%(port)s' % cnodes[i]
            headers['X-Container-Device'] = cnodes[i]['device']

            if lifecycle:
                headers['content-length'] = len(lifecycle)
                headers['etags'] = self._compute_md5(lifecycle)
                headers['content-type'] = 'text/plain'

            conn = http_connect(ip, port, dev, part, method, path,
                                headers)

            if method == 'PUT':
                conn.send(lifecycle)

            response = conn.getresponse()
            i += 1
        return response

    def reload(self):
        self._initialize()

    def _compute_md5(self, value):
        v = md5()
        v.update(value)
        return v.hexdigest()


class ObjectLifecycle(LifecycleCommon):
    def __init__(self, account, container, obj, swift_client=None,
                 env=None, app=None):
        LifecycleCommon.__init__(self, account, container,
                                 swift_client=swift_client,
                                 env=env, app=app)
        self.path = '/v1/%s/%s/%s' % (account, container, obj)
        self.obj_name = obj
        self._initialize()

    def get_rules_actions(self):
        if not self.headers:
            return None

        lifecycle = dict()

        for meta_prefix in (OBJECT_LIFECYCLE_META['Expiration'],
                            OBJECT_LIFECYCLE_META['Transition']):
            id_meta = meta_prefix + "Rule-Id"
            rule_id = self.headers.get(id_meta, None)
            if not rule_id:
                continue

            action = meta_prefix.split('-', 5)[4]
            lifecycle['%s-Id' % action] = rule_id
            lifecycle[action] = self.headers[meta_prefix + 'Last-Modified']
            lifecycle[action + '-Status'] = 'Enabled'

        if len(lifecycle) == 0:
            return None

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
        self.obj = obj
        self.object = ObjectLifecycle(account, container, obj, env=env,
                                      app=app, swift_client=swift_client)
        self.container = ContainerLifecycle(account, container, env=env,
                                            app=app,
                                            swift_client=swift_client)

    def get_s3_storage_class(self):
        return self.object.get_s3_storage_class()

    def get_object_rule_by_action(self, action):
        rules = self.container.get_rules_by_object_name(self.obj)

        for rule in rules:
            if action in rule:
                return rule

        return None

    def object_lifecycle_validation(self):
        if 'X-Object-Manifest' in self.object.headers:
            return SKIP_THIS_OBJECT

        obj_name = self.object.obj_name
        c_rule = self.container.get_rule_actions_by_object_name(obj_name)
        o_rule = self.object.get_rules_actions()

        rule_status = None
        if c_rule:
            if o_rule:
                if c_rule == o_rule:
                    return LIFECYCLE_OK

                for key in ('Expiration', 'Transition'):
                    if (key not in c_rule and key in o_rule) or \
                            (key in c_rule and key not in o_rule):
                        return CONTAINER_LIFECYCLE_IS_UPDATED

                    elif key not in c_rule and key not in o_rule:
                        continue

                    if c_rule[key] == o_rule[key]:
                        if c_rule[key + '-Status'].lower() == 'disabled':
                            if rule_status:
                                rule_status = DISABLED_BOTH
                                break
                            if key == 'Expiration':
                                rule_status = DISABLED_EXPIRATION
                            if key == 'Transition':
                                rule_status = DISABLED_TRANSITION
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
        return rule_status

    def reload(self):
        self.object.reload()
        self.container.reload()


def calc_when_actions_do(rule, from_time):
    actions_timestamp = dict()

    for key in ('Expiration', 'Transition'):
        if key not in rule:
            continue
        action = rule[key]
        time = None
        if 'Date' in action:
            time = calendar.timegm(dateutil.parser.parse(action['Date'])
            .timetuple())
        elif 'Days' in action:
            time = calc_nextDay(from_time) + int(action['Days']) * DAY_SECONDS
            time = normalize_delete_at_timestamp(time)
        actions_timestamp[key] = time
    return actions_timestamp


def calc_nextDay(timestamp):
    current = normalize_delete_at_timestamp((int(timestamp) / DAY_SECONDS) *
                                            DAY_SECONDS)
    return int(current) + DAY_SECONDS