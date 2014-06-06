# coding=utf-8
from swift.common.swob import Request, Response
from swift.common.utils import get_logger, split_path
from swift.common.wsgi import WSGIContext
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_REQUEST_ENTITY_TOO_LARGE

from exceptions import LifecycleConfigurationException
from utils import *
import ast
from operator import itemgetter


LifeCycle_Response_Header = 'X-Lifecycle-Response'
LifeCycle_Sysmeta = 'X-Container-Sysmeta-Lifecycle'


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


class LifecyclePropagateController(WSGIContext):
    """
    Lifecycle propagate Controller to PUT Object
    """

    def __init__(self, app):
        WSGIContext.__init__(self, app)


class LifecycleManageController(WSGIContext):
    def __init__(self, app):
        WSGIContext.__init__(self, app)

    def GET(self, env, start_response):
        req = Request(env)

        req.method = 'HEAD'

        resp = req.get_response(self.app)
        status = get_status_int(resp.status)
        req.method = 'GET'

        if status is not HTTP_NO_CONTENT:
            return resp

        if LifeCycle_Sysmeta in resp.headers and resp.headers[LifeCycle_Sysmeta] != 'None':
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
                return Response(status=400, body=e.message, headers={LifeCycle_Response_Header: True})

        ret = Response(request=req, body=lifecycle, headers={LifeCycle_Response_Header: True})
        return ret

    def DELETE(self, env, start_response):
        req = Request(env)

        req.method = 'HEAD'
        resp = req.get_response(self.app)

        status = get_status_int(resp.status)

        if status is not HTTP_NO_CONTENT:
            return resp

        if LifeCycle_Sysmeta in resp.headers:

            if 'lifecycle' in req.params:
                req.method = 'POST'
                req.headers[LifeCycle_Sysmeta] = 'None'
                req.get_response(self.app)
            elif 'lifecycle_rule' in req.params:
                id = req.params['lifecycle_rule']
                lifecycle = ast.literal_eval(resp.headers[LifeCycle_Sysmeta])
                req.method = 'POST'
                newl = filter(lambda x : x.get('ID') != id, lifecycle)
                if not newl:
                    newl = 'None'
                req.headers[LifeCycle_Sysmeta] = newl
                req.get_response(self.app)

        req.method = 'DELETE'
        return Response(status=HTTP_NO_CONTENT)


    def PUT(self, env, start_response):
        req = Request(env)
        lifecycle_xml = req.body
        try:
            lifecycle = xml_to_list(lifecycle_xml)
            # 이전 Lifecycle을 가져옴

            req.method = "HEAD"
            resp = req.get_response(self.app)

            prevLifecycle = None
            if LifeCycle_Sysmeta in resp.headers and resp.headers[LifeCycle_Sysmeta] != 'None':
                prevLifecycle = resp.headers[LifeCycle_Sysmeta]

            if 'lifecycle' in req.params:

                if prevLifecycle is not None:
                    updateLifecycleMetadata(prevLifecycle, lifecycle)

                # Rule이 올바르게 설정되어 있는 지 검사
                validationCheck(lifecycle)

                # 새로운 lifecycle로 변경
                req.method = "POST"
                req.headers[LifeCycle_Sysmeta] = lifecycle

                req.get_response(self.app)

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
                req.method = "POST"
                req.headers[LifeCycle_Sysmeta] = prevLifecycle
                req.get_response(self.app)

        except LifecycleConfigurationException as e:
            env['REQUEST_METHOD'] = 'PUT'
            return get_err_response(e.message)

        req.method = 'PUT'
        return Response(status=200, app_iter='True', headers={LifeCycle_Response_Header: True})


class LifecycleMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.dapp = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

    def get_controller(self, env, path):
        req = Request(env)

        container, obj = split_path(path, 0, 2, True)

        if container:
            if 'lifecycle' in req.params or 'lifecycle_rule' in req.params:
                return LifecycleManageController
        return None

    def __call__(self, env, start_response):
        req = Request(env)
        self.logger.debug('Calling Lifecycle Middleware')

        controller = self.get_controller(env, req.path)

        if controller is None:
            return self.app(env, start_response)

        controller = controller(self.app)

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