# coding=utf-8
from swift.common.swob import Request, Response
from swift.common.utils import get_logger, split_path
from swift.common.wsgi import WSGIContext
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_REQUEST_ENTITY_TOO_LARGE

import xml.etree.ElementTree as ET


def get_err_response(code):
    """
    Given an HTTP response code, create a properly formatted xml error response

    :param code: error code
    :returns: webob.response object
    """
    error_table = {
        'AccessDenied':
            (HTTP_FORBIDDEN, 'Access denied'),
        'BucketAlreadyExists':
            (HTTP_CONFLICT, 'The requested bucket name is not available'),
        'BucketNotEmpty':
            (HTTP_CONFLICT, 'The bucket you tried to delete is not empty'),
        'InvalidArgument':
            (HTTP_BAD_REQUEST, 'Invalid Argument'),
        'InvalidBucketName':
            (HTTP_BAD_REQUEST, 'The specified bucket is not valid'),
        'InvalidURI':
            (HTTP_BAD_REQUEST, 'Could not parse the specified URI'),
        'InvalidDigest':
            (HTTP_BAD_REQUEST, 'The Content-MD5 you specified was invalid'),
        'BadDigest':
            (HTTP_BAD_REQUEST, 'The Content-Length you specified was invalid'),
        'EntityTooLarge':
            (HTTP_BAD_REQUEST, 'Your proposed upload exceeds the maximum '
                               'allowed object size.'),
        'NoSuchBucket':
            (HTTP_NOT_FOUND, 'The specified bucket does not exist'),
        'SignatureDoesNotMatch':
            (HTTP_FORBIDDEN, 'The calculated request signature does not '
                             'match your provided one'),
        'RequestTimeTooSkewed':
            (HTTP_FORBIDDEN, 'The difference between the request time and the'
                             ' current time is too large'),
        'NoSuchKey':
            (HTTP_NOT_FOUND, 'The resource you requested does not exist'),
        'Unsupported':
            (HTTP_NOT_IMPLEMENTED, 'The feature you requested is not yet'
                                   ' implemented'),
        'MissingContentLength':
            (HTTP_LENGTH_REQUIRED, 'Length Required'),
        'ServiceUnavailable':
            (HTTP_SERVICE_UNAVAILABLE, 'Please reduce your request rate')}

    resp = Response(content_type='text/xml')
    resp.status = error_table[code][0]
    resp.body = '<?xml version="1.0" encoding="UTF-8"?>\r\n<Error>\r\n  ' \
                '<Code>%s</Code>\r\n  <Message>%s</Message>\r\n</Error>\r\n' \
                % (code, error_table[code][1])
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

        # 요청을 HEAD로 변환하여 Container 의 metadata를 가져옴
        req.method = 'HEAD'
        resp = req.get_response(self.app)

        lifecycle_dict = resp.headers['X-Container-Sysmeta-Lifecycle']

        # 다시 원래 요청으로 되돌림.
        req.method = 'GET'
        ret = Response(request=req, body=lifecycle_dict)
        return ret

    def DELETE(self, env, start_response):
        print 'delete'
        return Response()


    def PUT(self, env, start_response):
        req = Request(env)
        lifecycle_xml = req.body

        doc = self.xmltodict(lifecycle_xml)

        req.method = "POST"
        req.headers['X-Container-Sysmeta-Lifecycle'] = str(doc)

        req.get_response(self.app)
        return Response(status=201)

    def xmltodict(self, xml):
        """
        XML을 dictionary로 변환시켜줌.
        """
        return 'do something'


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
            if 'lifecycle' or 'lifecycle_rule' in req.params:
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