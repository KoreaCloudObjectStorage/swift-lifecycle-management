# coding=utf-8
from copy import copy
from swift.common.exceptions import DiskFileDeviceUnavailable
from swift.common.swob import Request, HTTPInsufficientStorage, HTTPAccepted
from swift.common.utils import get_logger
from swift.common.request_helpers import split_and_validate_path
from swift.obj.diskfile import DiskFileManager
from common.lifecycle import GLACIER_FLAG_META


class TruncateMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='truncate')
        self._diskfile_mgr = DiskFileManager(conf, self.logger)

    def truncate(self, env):
        req = Request(env)
        try:
            disk_file = self.get_diskfile(self.device, self.partition,
                                          self.account, self.container,
                                          self.obj)
        except DiskFileDeviceUnavailable:
            return HTTPInsufficientStorage(drive=self.device,
                                           request=Request(copy(env)))

        # TODO 기존에 저장되어 있던, S3 관련 meta를 제외한 나머지 metadata 저장

        # object flow 상, 임시 데이터를 삭제 후 DiskFileWrite 의 put을 하게 되면,
        # _finalize_put을 호출하게 된다. 이 때, metadata에 설정된 X-Timestamp 값으로
        # object 파일명을 생성하고, 임시 파일로 대체한다.
        # 따라서 별 다른 truncate를 할 필요가 없다.
        ori_meta = disk_file.get_metadata()
        metadata = {
            'X-Timestamp': ori_meta['X-Timestamp'],
            'Content-Type': ori_meta['Content-Type'],
            'ETag': ori_meta['ETag'],
            'Content-Length': ori_meta['Content_Length'],
            'X-Object-Meta-Glacier': True
        }

        with disk_file.create(size=0) as writer:
            writer.put(metadata)

        return HTTPAccepted(request=req)

    def get_diskfile(self, device, partition, account, container, obj,
                    **kwargs):
        return self._diskfile_mgr.get_diskfile(device, partition, account,
                                               container, obj, **kwargs)

    def __call__(self, env, start_response):
        req = Request(copy(env))
        method = req.method
        self.device, self.partition, self.account, self.container, \
            self.obj = split_and_validate_path(req, 5, 5, True)

        if method == 'POST' and GLACIER_FLAG_META in req.headers:
            return self.truncate(env)(env, start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def truncate_filter(app):
        return TruncateMiddleware(app, conf)

    return truncate_filter