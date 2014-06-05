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

        # TODO Container가 존재하지 않는 경우
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
                        '<Error><Code>NoSuchLifecycleConfiguration</Code>'\
                        '<Message>The lifecycle configuration does not exist</Message>'\
                        '<BucketName>%s</BucketName></Error>' % container
            resp.headers[LifeCycle_Response_Header] = True
            return resp

        lifecycle = list_to_xml(lifecycle)
        ret = Response(request=req, body=lifecycle, headers={LifeCycle_Response_Header: True})
        return ret

    def DELETE(self, env, start_response):
        req = Request(env)

        req.method = 'HEAD'
        resp = req.get_response(self.app)

        req.method = 'DELETE'
        status = get_status_int(resp.status)

        if status is not HTTP_NO_CONTENT:
            return resp

        if LifeCycle_Sysmeta in resp.headers:
            req.method = 'POST'
            req.headers[LifeCycle_Sysmeta] = 'None'
            resp = req.get_response(self.app)

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

            if prevLifecycle is not None:
                updateLifecycleMetadata(prevLifecycle, lifecycle)

            # Rule이 올바르게 설정되어 있는 지 검사
            validationCheck(lifecycle)

            # 새로운 lifecycle로 변경
            req.method = "POST"
            req.headers[LifeCycle_Sysmeta] = lifecycle

            resp = req.get_response(self.app)

            # env를 원래 상태로 되돌림.
            req.method = 'PUT'

        except LifecycleConfigurationException as e:
            env['REQUEST_METHOD'] = 'PUT'
            return get_err_response(e.message)

        return Response(status=201, app_iter='True', headers={LifeCycle_Response_Header: True})



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