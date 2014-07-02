# coding=utf-8
import ast
import time
import calendar
from datetime import datetime
from urllib2 import unquote
from operator import itemgetter
from copy import copy

from swift.common.swob import Request, Response
from swift.common.utils import get_logger, split_path, \
    normalize_delete_at_timestamp, \
    normalize_timestamp
from swift.common.wsgi import WSGIContext
from swift.common.http import HTTP_NO_CONTENT, HTTP_NOT_FOUND, HTTP_OK, \
    HTTP_FORBIDDEN
from swift.common.ring import Ring
from swift.common.bufferedhttp import http_connect
from exceptions import LifecycleConfigException
from utils import xml_to_list, dict_to_xml, list_to_xml, get_status_int, \
    updateLifecycleMetadata, validationCheck, is_Lifecycle_in_Header, \
    get_lifecycle_headers, calc_nextDay, day_seconds
from common.lifecycle import Object, CONTAINER_LIFECYCLE_NOT_EXIST, \
    LIFECYCLE_RESPONSE_HEADER, OBJECT_LIFECYCLE_NOT_EXIST, \
    CONTAINER_LIFECYCLE_IS_UPDATED, LIFECYCLE_ERROR, LIFECYCLE_OK, \
    CONTAINER_LIFECYCLE_SYSMETA


def get_err_response(err):
    """
    Given an HTTP response code, create a properly formatted xml error response

    :param code: error code
    :returns: webob.response object
    """

    resp = Response(content_type='text/xml')
    resp.status = err['code']
    resp.body = """<?xml version="1.0" encoding="UTF-8"?>
                   <Error><Code>%s</Code><Message>%s</Message></Error>""" \
                % (err['code'], err['msg'])
    resp.headers = {LIFECYCLE_RESPONSE_HEADER: True}
    return resp


class ObjectController(WSGIContext):

    def __init__(self, app, account, container_name, object_name, **kwargs):
        WSGIContext.__init__(self, app)
        self.account = account
        self.container = container_name
        self.object = object_name
        self.hidden_accounts = {'expiration': '.s3_expiring_objects',
                                'transition': '.s3_transitioning_objects'}
        self.container_ring = Ring('/etc/swift', ring_name='container')

    def GETorHEAD(self, env, start_response):
        o = Object(self.account, self.container, self.object, env=env,
                   app=self.app)

        http_status = o.o_lifecycle.get_status()
        headers = o.o_lifecycle.headers
        object_status = o.get_object_status()

        if http_status is not HTTP_OK:
            return Response(status=http_status)

        # convert object's last_modified(UTC TIME) to Unix Timestamp
        last_modified = datetime.strptime(headers['Last-Modified'],
                                          '%a, %d %b %Y %H:%M:%S GMT')
        last_modified = calendar.timegm(last_modified.utctimetuple())

        # Glacier로 Transition 된 Object 일 경우
        if object_status == 'GLACIER' and env['REQUEST_METHOD'] == 'GET':
            body = '<Error>\n' \
                   '<Code>InvalidObjectState</Code>\n' \
                   '<Message>The operation is not valid ' \
                   'for the object\'s storage class</Message>\n' \
                   '</Error>\n'
            resp = Response(headers=headers)
            resp.body = body
            resp.status = HTTP_FORBIDDEN
            resp.headers[LIFECYCLE_RESPONSE_HEADER] = True
            return resp

        obj_lc_status = o.object_lifecycle_validation()

        if obj_lc_status == CONTAINER_LIFECYCLE_NOT_EXIST:
            # Setting Object's Lifecycle to empty
            req = Request(copy(env))
            req.method = 'POST'
            req.headers = headers
            req.get_response(self.app)

        elif obj_lc_status in (OBJECT_LIFECYCLE_NOT_EXIST,
                               CONTAINER_LIFECYCLE_IS_UPDATED):

            # Update object meta to container LC
            new_header, actionList =\
                get_lifecycle_headers(
                    o.c_lifecycle.get_rule_by_prefix(self.object),
                    last_modified)
            req = Request(copy(env))
            req.method = 'POST'
            req.headers.update(new_header)
            req.get_response(self.app)

            #Update Hidden Information
            container_timestamp = \
                o.c_lifecycle.get_action_timestamp_by_prefix(self.account)

            for key in container_timestamp:
                self.hidden_update(env, hidden={
                    'account': self.hidden_accounts[key.lower()],
                    'container': actionList[key.lower()]
                }, orig={
                    'account': self.account,
                    'container': self.container,
                    'object': self.object
                })
        elif obj_lc_status == LIFECYCLE_ERROR:
            return Response(status=HTTP_NOT_FOUND)

        req = Request(env)
        resp = req.get_response(self.app)

        if obj_lc_status not in (LIFECYCLE_OK,
                                 OBJECT_LIFECYCLE_NOT_EXIST,
                                 CONTAINER_LIFECYCLE_IS_UPDATED):
            return resp

        object_lifecycle = o.get_object_lifecycle()
        headers = dict()
        if 'Expiration' in object_lifecycle:
            expiration = object_lifecycle['Expiration']
            if 'Days' in expiration:
                expire_time = calc_nextDay(last_modified) + \
                              int(expiration['Days']) * day_seconds
                expire_at = normalize_delete_at_timestamp(expire_time)
            elif 'Date' in expiration:
                expire_date = datetime.strptime(expiration['Date'],
                                                "%Y-%m-%dT%H:%M:%S+00:00")
                expire_at = calendar.timegm(expire_date.timetuple())

            expire_date = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                        time.gmtime(float(expire_at)))
            headers['X-Amz-Expiration'] = 'expiry-date="%s", rule-id="%s"' \
                                          % (expire_date,
                                             object_lifecycle['ID'])
        resp.headers.update(headers)
        return resp

    def GET(self, env, start_response):
        return self.GETorHEAD(env, start_response)

    def DELETE(self, env, start_response):
        return self.app(env, start_response)

    def HEAD(self, env, start_response):
        return self.GETorHEAD(env, start_response)

    def PUT(self, env, start_response):
        req = Request(copy(env))
        req.method = 'HEAD'
        req.path_info = '/v1/%s/%s' % (self.account, self.container)
        resp = req.get_response(self.app)
        status = get_status_int(resp.status)
        if status is not HTTP_NO_CONTENT:
            return resp

        actionList = dict()
        headers = dict()

        if is_Lifecycle_in_Header(resp.headers):
            lifecycle = ast.literal_eval(resp.headers[CONTAINER_LIFECYCLE_SYSMETA])

            for rule in lifecycle:
                prefix = rule['Prefix']
                if self.object.startswith(prefix):
                    headers, actionList = get_lifecycle_headers(rule,
                                                                time.time())
                    break

            if actionList:
                for action, at_time in actionList.iteritems():
                    hidden_account = self.hidden_accounts[action]
                    action_at = at_time
                    self.hidden_update(env, hidden=dict({
                        'account': hidden_account,
                        'container': action_at
                    }), orig=dict({
                        'account': self.account,
                        'container': self.container,
                        'object': self.object
                    }))

        req = Request(env)
        req.headers.update(headers)

        return req.get_response(self.app)

    def hidden_update(self, env, hidden, orig):
        hidden_obj = '%s/%s/%s' % (orig['account'], orig['container'],
                                   orig['object'])
        hidden_path = '/%s/%s/%s' % (hidden['account'], hidden['container'],
                                     hidden_obj)
        part, nodes = self.container_ring.get_nodes(hidden['account'],
                                                    str(hidden['container']))
        for node in nodes:
            ip = node['ip']
            port = node['port']
            dev = node['device']
            action_headers = dict()
            action_headers['user-agent'] = 'lifecycle'
            action_headers['X-Timestamp'] = normalize_timestamp(time.time())
            action_headers['referer'] = Request(copy(env)).as_referer()
            action_headers['x-size'] = '0'
            action_headers['x-content-type'] = "text/plain"
            action_headers['x-etag'] = 'd41d8cd98f00b204e9800998ecf8427e'

            conn = http_connect(ip, port, dev, part, "PUT", hidden_path,
                                action_headers)
            response = conn.getresponse()
            response.read()


class LifecycleManageController(WSGIContext):
    def __init__(self, app, **kwargs):
        WSGIContext.__init__(self, app)

    def GET(self, env, start_response):
        req = Request(env)

        req.method = 'HEAD'

        resp = req.get_response(self.app)
        status = get_status_int(resp.status)
        req.method = 'GET'

        if status is not HTTP_NO_CONTENT:
            return resp

        if is_Lifecycle_in_Header(resp.headers):
            lifecycle = resp.headers[CONTAINER_LIFECYCLE_SYSMETA]

        else:
            container, obj = split_path(req.path, 0, 2, True)

            resp = Response(content_type='text/xml')
            resp.status = HTTP_NOT_FOUND
            resp.body = '<?xml version="1.0" encoding="UTF-8"?>' \
                        '<Error><Code>NoSuchLifecycleConfiguration</Code>' \
                        '<Message>The lifecycle configuration' \
                        ' does not exist</Message>' \
                        '<BucketName>%s</BucketName></Error>' % container
            resp.headers[LIFECYCLE_RESPONSE_HEADER] = True
            return resp

        lifecycle = ast.literal_eval(lifecycle)

        if 'lifecycle' in req.params:
            lifecycle = list_to_xml(lifecycle)

        elif 'lifecycle_rule' in req.params:
            try:
                lc_map = map(itemgetter('ID'), lifecycle)
                index = lc_map.index(req.params['lifecycle_rule'])
                lifecycle = lifecycle[index]
                lifecycle = dict_to_xml(lifecycle)
            except Exception as e:
                # TODO rule 별 조회시 해당 ID가 없을 경우 메세지 내용 알아보기
                return Response(status=400, body=e.message,
                                headers={LIFECYCLE_RESPONSE_HEADER: True})

        ret = Response(request=req, body=lifecycle,
                       headers={LIFECYCLE_RESPONSE_HEADER: True})
        return ret

    def DELETE(self, env, start_response):
        req = Request(copy(env))
        req.method = 'HEAD'
        resp = req.get_response(self.app)

        status = get_status_int(resp.status)

        if status is not HTTP_NO_CONTENT:
            return resp

        if CONTAINER_LIFECYCLE_SYSMETA in resp.headers:

            if 'lifecycle' in req.params:
                req = Request(copy(env))
                req.method = 'POST'
                req.headers[CONTAINER_LIFECYCLE_SYSMETA] = 'None'
                req.get_response(self.app)
            elif 'lifecycle_rule' in req.params:
                id = req.params['lifecycle_rule']
                lifecycle = ast.literal_eval(resp.headers[CONTAINER_LIFECYCLE_SYSMETA])
                newlifecycle = filter(lambda x : x.get('ID') != id, lifecycle)
                if not newlifecycle:
                    newlifecycle = 'None'

                req = Request(copy(env))
                req.method = 'POST'
                req.headers[CONTAINER_LIFECYCLE_SYSMETA] = newlifecycle
                req.get_response(self.app)

        return Response(status=HTTP_NO_CONTENT)


    def PUT(self, env, start_response):
        try:
            req = Request(copy(env))
            lifecycle_xml = req.body
            lifecycle = xml_to_list(lifecycle_xml)
            # 이전 Lifecycle을 가져옴

            req.method = "HEAD"
            resp = req.get_response(self.app)
            resp_status = get_status_int(resp.status)

            if resp_status is not HTTP_NO_CONTENT:
                return resp

            prevLifecycle = None
            if is_Lifecycle_in_Header(resp.headers):
                prevLifecycle = resp.headers[CONTAINER_LIFECYCLE_SYSMETA]

            if 'lifecycle' in req.params:

                if prevLifecycle is not None:
                    updateLifecycleMetadata(prevLifecycle, lifecycle)

                # Rule이 올바르게 설정되어 있는 지 검사
                validationCheck(lifecycle)

                # 새로운 lifecycle로 변경
                req = Request(copy(env))
                req.method = "POST"
                req.headers[CONTAINER_LIFECYCLE_SYSMETA] = lifecycle

                resp = req.get_response(self.app)
                resp_status = get_status_int(resp.status)

                if resp_status is not HTTP_NO_CONTENT:
                    return resp

            elif 'lifecycle_rule' in req.params:
                if len(lifecycle) > 1:
                    exceptMsg = dict()
                    exceptMsg['status'] = 400
                    exceptMsg['code'] = 'InvalidRequest'
                    exceptMsg['msg'] = 'more than one rule was uploaded'
                    raise LifecycleConfigException(exceptMsg)

                rule = lifecycle[0]
                prefix = rule['Prefix']
                if prevLifecycle:

                    prevLifecycle = ast.literal_eval(prevLifecycle)
                    if any(r['ID'] == rule['ID'] for r in prevLifecycle):
                        # TODO ID 가 같아도, 안의 설정에 따라서 오류, 정상 처리 적용하기
                        message = '<?xml version="1.0" encoding="UTF-8"?>' \
                                  '<Error><Code>InvalidArgument</Code>' \
                                  '<Message>Rule ID must be unique. ' \
                                  'Found same ID ' \
                                  'for more than one rule</Message>' \
                                  '<ArgumentValue>%s</ArgumentValue>' \
                                  '<ArgumentName>ID</ArgumentName>' \
                                  % rule['ID']
                        req.method = 'PUT'
                        return Response(status=400, body=message,
                                        headers={
                                            LIFECYCLE_RESPONSE_HEADER: True
                                        })

                    for prev in prevLifecycle:
                        if prefix.startswith(prev['Prefix']) or\
                           prev['Prefix'].startswith(prefix):
                            if 'Transition' in rule.keys() and \
                               'Transition' in prev.keys():
                                exceptMsg = dict()
                                exceptMsg['status'] = 400
                                exceptMsg['code'] = 'InvalidRequest'
                                exceptMsg['msg'] = \
                                    'Found overlapping prefixes \'%s\' ' \
                                    'and \'%s\' for same action type \'%s\'' \
                                    % (prefix, prev['Prefix'], 'Transition')
                                raise LifecycleConfigException(exceptMsg)

                            if 'Expiration' in rule.keys() and \
                               'Expiration' in prev.keys():
                                exceptMsg = dict()
                                exceptMsg['status'] = 400
                                exceptMsg['code'] = 'InvalidRequest'
                                exceptMsg['msg'] = 'Found overlapping ' \
                                                   'prefixes \'%s\' and ' \
                                                   '\'%s\' for same ' \
                                                   'action type \'%s\'' \
                                                   % (prefix,
                                                      prev['Prefix'],
                                                      'Expiration')
                                raise LifecycleConfigException(exceptMsg)

                            if 'Expiration' in (rule.keys() or prev.keys()) \
                                and \
                               'Transition' in (rule.keys() or prev.keys()):

                                if 'Days' in (rule.keys() or prev.keys()) and \
                                   'Date' in (rule.keys() or prev.keys()):
                                    exceptMsg = dict()
                                    exceptMsg['status'] = 400
                                    exceptMsg['code'] = 'InvalidRequest'
                                    exceptMsg['msg'] = \
                                        'Found mixed \'Date\' and \'Days\' ' \
                                        'based Expiration and Transition ' \
                                        'actions in lifecycle rule for ' \
                                        'prefix \'%s\'' % prefix
                                    raise LifecycleConfigException(exceptMsg)

                else:
                    prevLifecycle = list()

                prevLifecycle.append(rule)
                req = Request(copy(env))
                req.method = "POST"
                req.headers[CONTAINER_LIFECYCLE_SYSMETA] = prevLifecycle
                resp = req.get_response(self.app)
                resp_status = get_status_int(resp.status)

                if resp_status is not HTTP_NO_CONTENT:
                    return resp

        except LifecycleConfigException as e:
            env['REQUEST_METHOD'] = 'PUT'
            return get_err_response(e.message)

        return Response(status=200, app_iter='True',
                        headers={LIFECYCLE_RESPONSE_HEADER: True})


class LifecycleMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

    def get_controller(self, env, path):
        req = Request(env)
        version, account, container, obj = split_path(path, 0, 4, True)
        d = {'container_name': container,
             'object_name': unquote(obj) if obj is not None else obj,
             'account': account}

        if container:
            if 'lifecycle' in req.params or 'lifecycle_rule' in req.params:
                return LifecycleManageController, d

        if container and obj:
            return ObjectController, d

        return None, d

    def __call__(self, env, start_response):
        req = Request(env)
        self.logger.debug('Calling Lifecycle Middleware')

        controller, path_parts = self.get_controller(env, req.path)

        if controller is None:
            return self.app(env, start_response)

        controller = controller(self.app, **path_parts)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(env, start_response)
        else:
            return get_err_response({'code': 400,
                                     'msg': 'InvalidURI'})(env, start_response)

        return res(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return LifecycleMiddleware(app, conf)

    return lifecycle_filter