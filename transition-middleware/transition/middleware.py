# coding=utf-8
from copy import copy
from swift.common.bufferedhttp import http_connect
from swift.common.ring import Ring
from swift.common.swob import Request
from swift.common.utils import get_logger, split_path, normalize_timestamp
import time
from common.lifecycle import GLACIER_FLAG_META


class TransitionMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='transition')
        self.container_ring = Ring('/etc/swift', ring_name='container')
        self.glacier_account_prefix = '.glacier_'

    def transition(self, env):
        # GET Object body
        req = Request(copy(env))
        req.method = 'GET'
        resp = req.get_response(self.app)
        # TODO 헤더에서 User-Metadata만 가져올 것
        obj_header = resp.headers
        obj_body = resp.body

        # TODO Glacier로 업로드
        glacier_obj = '%s/%s/%s' % (self.account, self.container, self.obj)

        # Object를 0KB로 만들기
        req = Request(copy(env))
        req.headers[GLACIER_FLAG_META] = True
        resp = req.get_response(self.app)

        # Glacier Hidden account에 기록
        glacier_account = self.glacier_account_prefix + self.account
        part, nodes = self.container_ring.get_nodes(glacier_account,
                                                    self.container)

        for node in nodes:
            ip = node['ip']
            port = node['port']
            dev = node['device']
            headers = dict()
            headers['user-agent'] = 'transition-middleware'
            headers['X-Timestamp'] = normalize_timestamp(time.time())
            headers['referer'] = req.as_referer()
            headers['x-size'] = '0'
            headers['x-content-type'] = 'text/plain'
            headers['x-etag'] = 'd41d8cd98f00b204e9800998ecf8427e'

            conn = http_connect(ip, port, dev, part, 'PUT', glacier_obj,
                                headers)
            conn.getresponse().read()

    def __call__(self, env, start_response):
        req = Request(env)
        method = req.method
        self.version, self.account, self.container, self.obj = split_path(
            req.path, 0, 4, True)
        if not self.obj:
            return self.app(env, start_response)

        if method == 'POST' and \
           'X-S3-Object-Transition' in req.headers:
            return self.transition(env)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def transition_filter(app):
        return TransitionMiddleware(app, conf)

    return transition_filter