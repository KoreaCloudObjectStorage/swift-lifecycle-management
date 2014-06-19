# coding=utf-8
import ast
import time
import calendar
import re
from datetime import datetime
from urllib2 import unquote
from operator import itemgetter
from copy import copy

from swift.common.swob import Request, Response
from swift.common.utils import get_logger, split_path, normalize_delete_at_timestamp, normalize_timestamp
from swift.common.wsgi import WSGIContext
from swift.common.http import HTTP_NO_CONTENT, HTTP_NOT_FOUND, HTTP_OK
from swift.common.ring import Ring
from swift.common.bufferedhttp import http_connect
from exceptions import LifecycleConfigurationException
from utils import xml_to_list, dict_to_xml, list_to_xml, get_status_int, updateLifecycleMetadata, validationCheck,\
    is_Lifecycle_in_Header, LifeCycle_Sysmeta, LifeCycle_Response_Header, get_lifecycle_headers, calc_nextDay,\
    day_seconds, outbound_filter


def get_err_response(err):
    """
    Given an HTTP response code, create a properly formatted xml error response

    :param code: error code
    :returns: webob.response object
    """

    resp = Response(content_type='text/xml')
    resp.status = err['status']
    resp.body = """<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>""" \
                % (err['code'], err['msg'])
    resp.headers = {LifeCycle_Response_Header: True}
    return resp


class ObjectController(WSGIContext):

    def __init__(self, app, account, container_name, object_name, **kwargs):
        WSGIContext.__init__(self, app)
        self.account = account
        self.container = container_name
        self.object = object_name
        self.hidden_accounts = {'expire': '.s3_expiring_objects', 'transition': '.s3_transitioning_objects'}
        self.container_ring = Ring('/etc/swift', ring_name='container')

    def GETorHEAD(self, env, start_response):
        req = Request(copy(env))
        resp = req.get_response(self.app)
        status = get_status_int(resp.status)
        rule_id_meta = 'X-Object-Meta-Rule-Id'
        if status is not HTTP_OK:
            return resp

        # convert last_modified(UTC TIME) to Unix Timestamp
        last_modified = datetime.strptime(resp.headers['Last-Modified'], '%a, %d %b %Y %H:%M:%S GMT')
        last_modified = calendar.timegm(last_modified.utctimetuple())
        if rule_id_meta in resp.headers:
            rule_id = resp.headers[rule_id_meta]

            # GET Lifecycle by rule id
            path = "/v1/%s/%s" % (self.account, self.container)
            req = Request(copy(env))
            req.method = "HEAD"
            req.path_info = path
            l_resp = req.get_response(self.app)
            if get_status_int(l_resp.status) is HTTP_NO_CONTENT:
                lifecycle = ast.literal_eval(l_resp.headers[LifeCycle_Sysmeta])
            else:
                return self.app

            lifecycle = lifecycle[map(itemgetter('ID'), lifecycle).index(rule_id)]
            if 'Expiration' in lifecycle:
                expiration = lifecycle['Expiration']
                if 'Days' in expiration:
                    expire_at = normalize_delete_at_timestamp(calc_nextDay(last_modified) \
                                                       + int(expiration['Days'])*day_seconds)
                elif 'Date' in expiration:
                    expire_at = calendar.timegm(\
                        datetime.strptime(expiration['Date'], "%Y-%m-%dT%H:%M:%S+00:00").timetuple())

                expire_date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(float(expire_at)))
                resp.headers['X-Amz-Expiration'] = 'expiry-date="%s", rule-id="%s"' % (expire_date, rule_id)

        # 불필요한 header 제거
        reg = re.compile('|'.join(outbound_filter), re.IGNORECASE).match
        removed = filter(reg, resp.headers)

        if removed:
            for r in removed:
                resp.headers.pop(r)

        return resp

    def GET(self, env, start_response):
        return self.GETorHEAD(env, start_response)

    def POST(self, env, start_response):
        pass

    def DELETE(self, env, start_response):
        pass

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
            lifecycle = ast.literal_eval(resp.headers[LifeCycle_Sysmeta])

            for rule in lifecycle:
                prefix = rule['Prefix']
                if self.object.startswith(prefix):
                    headers, actionList = get_lifecycle_headers(rule)
                    headers['X-Object-Meta-Rule-Id'] = rule['ID']
                    break

            if actionList:
                for action, at_time in actionList.iteritems():
                    hidden_account = self.hidden_accounts[action]
                    action_at = at_time
                    part, nodes = self.container_ring.get_nodes(hidden_account, str(action_at))
                    action_object = "%s/%s/%s" % (self.account, self.container, self.object)
                    action_path = '/%s/%s/%s' % (hidden_account, action_at, action_object)
                    for node in nodes:
                        ip = node['ip']
                        port = node['port']
                        dev = node['device']
                        action_headers = dict()
                        action_headers['user-agent'] = 'lifecycle-middleware'
                        action_headers['X-Timestamp'] = normalize_timestamp(time.time())
                        action_headers['referer'] = Request(copy(env)).as_referer()
                        action_headers['x-size'] = '0'
                        action_headers['x-content-type'] = "text/plain"
                        action_headers['x-etag'] = 'd41d8cd98f00b204e9800998ecf8427e'

                        conn = http_connect(ip, port, dev, part, "PUT", action_path, action_headers)
                        response = conn.getresponse()
                        response.read()

        req = Request(env)
        for key, value in headers.iteritems():
            req.headers.__setitem__(key, value)
        return req.get_response(self.app)


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
            lifecycle = resp.headers[LifeCycle_Sysmeta]

        else:
            container, obj = split_path(req.path, 0, 2, True)

            resp = Response(content_type='text/xml')
            resp.status = HTTP_NOT_FOUND
            resp.body = '<?xml version="1.0" encoding="UTF-8"?>' \
                        '<Error><Code>NoSuchLifecycleConfiguration</Code>' \
                        '<Message>The lifecycle configuration does not exist</Message>' \
                        '<BucketName>%s</BucketName></Error>' % container
            resp.headers[LifeCycle_Response_Header] = True
            return resp

        lifecycle = ast.literal_eval(lifecycle)

        if 'lifecycle' in req.params:
            lifecycle = list_to_xml(lifecycle)

        elif 'lifecycle_rule' in req.params:
            try:
                lifecycle = lifecycle[map(itemgetter('ID'), lifecycle).index(req.params['lifecycle_rule'])]
                lifecycle = dict_to_xml(lifecycle)
            except Exception as e:
                # TODO rule 별 조회시 해당 ID가 없을 경우 메세지 내용 알아보기
                return Response(status=400, body=e.message, headers={LifeCycle_Response_Header: True})

        ret = Response(request=req, body=lifecycle, headers={LifeCycle_Response_Header: True})
        return ret

    def DELETE(self, env, start_response):
        req = Request(copy(env))
        req.method = 'HEAD'
        resp = req.get_response(self.app)

        status = get_status_int(resp.status)

        if status is not HTTP_NO_CONTENT:
            return resp

        if LifeCycle_Sysmeta in resp.headers:

            if 'lifecycle' in req.params:
                req = Request(copy(env))
                req.method = 'POST'
                req.headers[LifeCycle_Sysmeta] = 'None'
                req.get_response(self.app)
            elif 'lifecycle_rule' in req.params:
                id = req.params['lifecycle_rule']
                lifecycle = ast.literal_eval(resp.headers[LifeCycle_Sysmeta])
                newlifecycle = filter(lambda x : x.get('ID') != id, lifecycle)
                if not newlifecycle:
                    newlifecycle = 'None'

                req = Request(copy(env))
                req.method = 'POST'
                req.headers[LifeCycle_Sysmeta] = newlifecycle
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
                prevLifecycle = resp.headers[LifeCycle_Sysmeta]

            if 'lifecycle' in req.params:

                if prevLifecycle is not None:
                    updateLifecycleMetadata(prevLifecycle, lifecycle)

                # Rule이 올바르게 설정되어 있는 지 검사
                validationCheck(lifecycle)

                # 새로운 lifecycle로 변경
                req = Request(copy(env))
                req.method = "POST"
                req.headers[LifeCycle_Sysmeta] = lifecycle

                resp = req.get_response(self.app)
                resp_status = get_status_int(resp.status)

                if resp_status is not HTTP_NO_CONTENT:
                    return resp

            elif 'lifecycle_rule' in req.params:
                if len(lifecycle) > 1:
                    exceptionMsg = dict()
                    exceptionMsg['status'] = 400
                    exceptionMsg['code'] = 'InvalidRequest'
                    exceptionMsg['msg'] = 'more than one rule was uploaded'
                    raise LifecycleConfigurationException(exceptionMsg)

                rule = lifecycle[0]
                prefix = rule['Prefix']
                if prevLifecycle:

                    prevLifecycle = ast.literal_eval(prevLifecycle)
                    if any(r['ID'] == rule['ID'] for r in prevLifecycle):
                        # TODO ID 가 같아도, 안의 설정에 따라서 오류, 정상 처리 적용하기
                        message = '<?xml version="1.0" encoding="UTF-8"?>' \
                                  '<Error><Code>InvalidArgument</Code>' \
                                  '<Message>Rule ID must be unique. Found same ID ' \
                                  'for more than one rule</Message>' \
                                  '<ArgumentValue>%s</ArgumentValue>' \
                                  '<ArgumentName>ID</ArgumentName>' % rule['ID']
                        req.method = 'PUT'
                        return Response(status=400, body=message, headers={LifeCycle_Response_Header: True})

                    for prev in prevLifecycle:
                        if prefix.startswith(prev['Prefix']) or prev['Prefix'].startswith(prefix):
                            if 'Transition' in rule.keys() and 'Transition' in prev.keys():
                                exceptionMsg = dict()
                                exceptionMsg['status'] = 400
                                exceptionMsg['code'] = 'InvalidRequest'
                                exceptionMsg['msg'] = 'Found overlapping prefixes \'%s\' and \'%s\' ' \
                                                      'for same action type \'%s\'' \
                                                      % (prefix, prev['Prefix'], 'Transition')
                                raise LifecycleConfigurationException(exceptionMsg)

                            if 'Expiration' in rule.keys() and 'Expiration' in prev.keys():
                                exceptionMsg = dict()
                                exceptionMsg['status'] = 400
                                exceptionMsg['code'] = 'InvalidRequest'
                                exceptionMsg['msg'] = 'Found overlapping prefixes \'%s\' and \'%s\' ' \
                                                      'for same action type \'%s\'' \
                                                      % (prefix, prev['Prefix'], 'Expiration')
                                raise LifecycleConfigurationException(exceptionMsg)

                            if 'Expiration' in (rule.keys() or prev.keys()) and \
                               'Transition' in (rule.keys() or prev.keys()):

                                if 'Days' in (rule.keys() or prev.keys()) and \
                                   'Date' in (rule.keys() or prev.keys()):
                                    exceptionMsg = dict()
                                    exceptionMsg['status'] = 400
                                    exceptionMsg['code'] = 'InvalidRequest'
                                    exceptionMsg['msg'] = 'Found mixed \'Date\' and \'Days\' based Expiration' \
                                                          ' and Transition actions' \
                                                          'in lifecycle rule for prefix \'%s\'' % prefix
                                    raise LifecycleConfigurationException(exceptionMsg)

                else:
                    prevLifecycle = list()

                prevLifecycle.append(rule)
                req = Request(copy(env))
                req.method = "POST"
                req.headers[LifeCycle_Sysmeta] = prevLifecycle
                resp = req.get_response(self.app)
                resp_status = get_status_int(resp.status)

                if resp_status is not HTTP_NO_CONTENT:
                    return resp

        except LifecycleConfigurationException as e:
            env['REQUEST_METHOD'] = 'PUT'
            return get_err_response(e.message)

        return Response(status=200, app_iter='True', headers={LifeCycle_Response_Header: True})


class LifecycleMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

    def get_controller(self, env, path):
        req = Request(env)
        version, account, container, obj = split_path(path, 0, 4, True)
        d = {'container_name': container, 'object_name': unquote(obj) if obj is not None else obj, 'account': account}

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
            return get_err_response('InvalidURI')(env, start_response)

        return res(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return LifecycleMiddleware(app, conf)

    return lifecycle_filter