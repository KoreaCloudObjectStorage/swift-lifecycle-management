# coding=utf-8
from swift.common.exceptions import DiskFileDeviceUnavailable, ChunkReadTimeout, DiskFileNoSpace
from swift.common.request_helpers import split_and_validate_path, is_user_meta
from swift.common.swob import Request, HTTPInsufficientStorage, HTTPRequestTimeout, HTTPCreated
from swift.common.utils import get_logger
from hashlib import md5


class RestoreMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='restore')

    def __call__(self, env, start_response):
        req = Request(env)

        self.device, self.partition, self.account, self.container, \
            self.obj = split_and_validate_path(req, 5, 5, True)

        if req.method == 'PUT' and 'X-Object-Meta-S3-Restored' in req.headers:
            return self.save_object(env)(env, start_response)

        if req.method == 'PUT' and 'X-Object-Meta-S3-Restore' in req.headers:
            return self.set_restoring(env)

        return self.app(env, start_response)

    def save_object(self, env):
        req = Request(env)
        try:
            disk_file = self.get_diskfile(self.device, self.partition,
                                          self.account, self.container,
                                          self.obj)
        except DiskFileDeviceUnavailable:
            return HTTPInsufficientStorage(drive=self.device,
                                           request=Request(env))
        ori_meta = disk_file.read_metadata()
        metadata = {}
        metadata.update(val for val in req.headers.iteritems()
                                if is_user_meta('object', val[0]))

        # Timestamp 값 유지
        metadata['X-Timestamp'] = ori_meta['X-Timestamp']
        metadata['Content-Type'] = ori_meta['Content-Type']
        fsize = req.message_length()
        etag = md5()
        try:
            with disk_file.create(size=fsize) as writer:
                def timeout_reader():
                        with ChunkReadTimeout(60):
                            return req.environ['wsgi.input'].read(65536)
                try:
                    for chunk in iter(lambda: timeout_reader(), ''):
                        etag.update(chunk)
                        writer.write(chunk)
                except ChunkReadTimeout:
                    return HTTPRequestTimeout(request=req)

                etag = etag.hexdigest()
                metadata['ETag'] = etag
                metadata['Content-Length'] = str(fsize)

                writer.put(metadata)
        except DiskFileNoSpace:
            return HTTPInsufficientStorage(drive=self.device, request=req)

        return HTTPCreated(request=req)

    def set_restoring(self, env):
        print 'a'

def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return RestoreMiddleware(app, conf)

    return lifecycle_filter
