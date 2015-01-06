# -*- coding: utf-8 -*-
import tempfile
import time
import os
from copy import copy

from boto.glacier.layer2 import Layer2

from swift.common.http import HTTP_NO_CONTENT, HTTP_INTERNAL_SERVER_ERROR
from swift.common.bufferedhttp import http_connect
from swift.common.ring import Ring
from swift.common.swob import Request, Response
from swift.common.utils import get_logger, split_path, normalize_timestamp

from swiftlifecyclemanagement.common.lifecycle import GLACIER_FLAG_META
from swiftlifecyclemanagement.common.utils import \
    make_glacier_hidden_object_name


class TransitionMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='transition')
        self.container_ring = Ring('/etc/swift', ring_name='container')
        self.glacier_account_prefix = '.glacier_'
        self.temp_path = conf.get('temp_path', '/var/cache/s3/')

    def _init_glacier(self):
        con = Layer2()
        return con.get_vault('swift-s3-transition')

    def transition(self, env):
        # GET Object body
        req = Request(copy(env))
        req.method = 'GET'
        resp = req.get_response(self.app)

        obj_body = resp.body

        # Glacier로 업로드
        tmpfile = self.save_to_tempfile(obj_body)
        try:
            glacier = self._init_glacier()
            archive_id = glacier.upload_archive(tmpfile)
            glacier_obj = make_glacier_hidden_object_name(self.obj, archive_id)
        except Exception as e:
            return Response(status=HTTP_INTERNAL_SERVER_ERROR, body=e.message)
        finally:
            self.delete_tempfile(tmpfile)

        # Object를 0KB로 만들기
        req = Request(copy(env))
        req.headers[GLACIER_FLAG_META] = True
        resp = req.get_response(self.app)

        # Glacier Hidden account에 기록
        glacier_account = self.glacier_account_prefix + self.account
        part, nodes = self.container_ring.get_nodes(glacier_account,
                                                    self.container)
        hidden_path = '/%s/%s/%s' % (glacier_account, self.container,
                                     glacier_obj)
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

            conn = http_connect(ip, port, dev, part, 'PUT', hidden_path,
                                headers)
            conn.getresponse().read()
        return Response(status=HTTP_NO_CONTENT)

    def save_to_tempfile(self, data):
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(bufsize=0, delete=False,
                                             dir=self.temp_path) as temp:
                temp.write(data)
                temp.flush()
                tmp_path = temp.name
        except Exception as e:
            self.logger.error(e)
        return tmp_path

    def delete_tempfile(self, tmppath):
        os.remove(tmppath)

    def __call__(self, env, start_response):
        req = Request(env)
        method = req.method
        self.version, self.account, self.container, self.obj = split_path(
            req.path, 0, 4, True)
        if not self.obj:
            return self.app(env, start_response)

        if method == 'POST' and \
           'X-S3-Object-Transition' in req.headers:
            return self.transition(env)(env, start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def transition_filter(app):
        return TransitionMiddleware(app, conf)

    return transition_filter