import ast
from copy import copy
from operator import itemgetter

from swift.common.http import is_success
from swift.common.swob import Request

# List of Lifecycle Comparison Result
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


class ContainerLifecycle(object):
    def __init__(self, account, container, swift_client=None, env=None,
                 app=None):
        self.swift_client = swift_client
        self.env = copy(env)
        self.app = app
        self.headers = None
        self.path = '/v1/%s/%s' % (account, container)
        self.__initialize()

    def get_action_timestamp_by_prefix(self, prefix):
        rule = self.get_rule_by_prefix(prefix)

        if not rule:
            return None

        rule_info = dict()
        rule_info['ID'] = rule['ID']
        for key in rule:
            if key in ('Expiration', 'Transition'):
                rule_info[key] = rule[key][key.lower()+'-last-modified']

        return rule_info

    def get_rule_by_prefix(self, prefix):
        lifecycle = self.get_lifecycle()

        if not lifecycle:
            return None

        prefixMap = map(itemgetter('Prefix'), lifecycle)

        prefixIndex = -1
        for p in prefixMap:
            if prefix.startswith(p):
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

    def __initialize(self):
        if self.swift_client:
            resp = self.swift_client.make_request('HEAD', self.path, {},
                                                  (2, 4))
        elif self.env:
            req = Request(self.env)
            req.method = 'HEAD'
            req.path_info = self.path
            resp = req.get_response(self.app)

        self.status = resp.status_int

        if is_success(self.status):
            self.headers = resp.headers

    def reload(self):
        self.__initialize()


class ObjectLifecycle(object):
    def __init__(self, account, container, object, swift_client=None,
                 env=None, app=None):
        self.swift_client = swift_client
        self.env = copy(env)
        self.app = app
        self.headers = None
        self.path = '/v1/%s/%s/%s' % (account, container, object)
        self.__initialize()

    def get_object_lifecycle_meta(self):
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

    def get_status(self):
        if not self.headers:
            return None

        if GLACIER_FLAG_META in self.headers:
            return 'GLACIER'
        return 'STANDARD'

    def __initialize(self):
        if self.swift_client:
            resp = self.swift_client.make_request('HEAD', self.path, {}, (2,))
        elif self.env:
            req = Request(self.env)
            req.method = 'HEAD'
            req.path_info = self.path
            resp = req.get_response(self.app)

        self.status = resp.status_int

        if is_success(self.status):
            self.headers = resp.headers

    def reload(self):
        self.__initialize()


class Object(object):
    def __init__(self, account, container, object, swift_client=None,
                 env=None, app=None):
        self.swift_client = swift_client
        self.env = env
        self.app = app
        self.account = account
        self.container = container
        self.object = object
        self.o_lifecycle = ObjectLifecycle(account, container, object,
                                           swift_client=swift_client,
                                           env=env, app=app)
        self.c_lifecycle = ContainerLifecycle(account, container,
                                              swift_client=swift_client,
                                              env=env, app=app)

    def get_object_status(self):
        return self.o_lifecycle.get_status()

    def get_object_lifecycle(self):
        lifecycle = self.c_lifecycle.get_lifecycle()

        object_meta = self.o_lifecycle.get_object_lifecycle_meta()

        if not lifecycle or not object_meta:
            return None

        id = object_meta['ID']
        return lifecycle[map(itemgetter('ID'), lifecycle).index(id)]

    def object_lifecycle_validation(self):
        container = \
            self.c_lifecycle.get_action_timestamp_by_prefix(self.object)
        object = self.o_lifecycle.get_object_lifecycle_meta()

        if container:
            if object:
                if container == object:
                    return LIFECYCLE_OK

                for key in ('Expiration', 'Transition'):
                    if (key not in self.c_lifecycle and
                       key in self .o_lifecycle) or \
                        (key in self.c_lifecycle and
                         key not in self.o_lifecycle):
                        return CONTAINER_LIFECYCLE_IS_UPDATED

                    if self.c_lifecycle[key] == self.o_lifecycle[key]:
                        continue
                    elif self.c_lifecycle[key] > self.o_lifecycle[key]:
                        return CONTAINER_LIFECYCLE_IS_UPDATED
                    elif self.c_lifecycle[key] < self.o_lifecycle[key]:
                        return LIFECYCLE_ERROR
            else:
                return OBJECT_LIFECYCLE_NOT_EXIST
        else:
            if object:
                return CONTAINER_LIFECYCLE_NOT_EXIST
            else:
                return LIFECYCLE_NOT_EXIST

    def reload(self):
        self.o_lifecycle.reload()
        self.c_lifecycle.reload()