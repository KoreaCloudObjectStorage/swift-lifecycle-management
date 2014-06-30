import ast
from operator import itemgetter

from swift.common.http import HTTP_NOT_FOUND, HTTP_CONFLICT, \
    HTTP_PRECONDITION_FAILED, is_success

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
LIFECYCLE_RESPONSE_HEADER = 'X-Lifecycle-Response'

OBJECT_LIFECYCLE_META = {
    'id': 'X-Object-Meta-S3-Lifecycle-Configuration-Rule-Id',
    'expire-last': 'X-Object-Meta-S3-Expiration-Last-Modified',
    'transition-last': 'X-Object-Meta-S3-Transition-Last-Modified'
}


class ContainerLifecycle(object):
    def __init__(self, swift_client, account, container):
        self.swift_client = swift_client
        self.headers = None
        self.path = '/v1/%s/%s' % (account, container)
        self.__initialize()

    def get_rule_by_prefix(self, prefix):
        if not self.headers and \
           CONTAINER_LIFECYCLE_SYSMETA not in self.headers:
            return None

        rule_list = ast.literal_eval(self.headers[CONTAINER_LIFECYCLE_SYSMETA])
        prefixMap = map(itemgetter('Prefix'), rule_list)

        prefixIndex = -1
        for p in prefixMap:
            if prefix.startswith(p):
                prefixIndex = prefixMap.index(p)
                break

        if prefixIndex < 0:
            return None

        rule = rule_list[prefixIndex]

        rule_info = dict()
        rule_info['ID'] = rule['ID']
        for key in rule:
            if key in ('Expiration', 'Transition'):
                rule_info[key] = rule[key][key.lower()+'-last-modified']

        return rule_info

    def __initialize(self):
        resp = self.swift_client.make_request('HEAD', self.path, {}, (2, 4))
        self.status = resp.status_int

        if is_success(self.status):
            self.headers = resp.headers


class ObjectLifecycle(object):
    def __init__(self, swift_client, account, container, object):
        self.swift_client = swift_client
        self.headers = None
        self.path = '/v1/%s/%s/%s' % (account, container, object)
        self.__initialize()

    def get_lifecycle(self):
        if not self.headers and OBJECT_LIFECYCLE_META['id'] in self.headers:
            return None

        lifecycle = dict()
        lifecycle['ID'] = self.headers[OBJECT_LIFECYCLE_META['id']]
        for key, value in self.headers.iteritems():
            if key in (OBJECT_LIFECYCLE_META['expire-last'],
                       OBJECT_LIFECYCLE_META['transition-last']):
                lifecycle[key.split('-', 5)[4]] = value
        return lifecycle

    def __initialize(self):
        resp = self.swift_client.make_request('HEAD', self.path, {}, (2,))
        self.status == resp.status_int

        if is_success(self.status):
            self.headers = resp.headers


def object_lifecycle_validation(swift_client, object_path):
    account, container, obj = object_path.split('/', 2)

    c_lifecycle = ContainerLifecycle(swift_client, account, container)
    o_lifecycle = ObjectLifecycle(swift_client, account, container, object)

    if c_lifecycle:
        if o_lifecycle:

            if c_lifecycle == o_lifecycle:
                return LIFECYCLE_OK

            for key in ('Expiration', 'Transition'):
                if key not in c_lifecycle and key in o_lifecycle or \
                   key in c_lifecycle and key not in o_lifecycle:
                    return CONTAINER_LIFECYCLE_IS_UPDATED

                if c_lifecycle[key] == o_lifecycle[key]:
                    continue
                elif c_lifecycle[key] > o_lifecycle[key]:
                    return CONTAINER_LIFECYCLE_IS_UPDATED
                elif c_lifecycle[key] < o_lifecycle[key]:
                    return LIFECYCLE_ERROR
        else:
            return OBJECT_LIFECYCLE_NOT_EXIST
    else:
        if o_lifecycle:
            return CONTAINER_LIFECYCLE_NOT_EXIST
        else:
            return LIFECYCLE_NOT_EXIST