# -*- coding: utf-8 -*-
# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import tempfile
import hashlib
from random import random
from time import time, strftime, gmtime
from os.path import join

from boto.glacier.layer2 import Layer2
from eventlet import sleep, Timeout
from eventlet.greenpool import GreenPool

from swift import gettext_ as _
from swift.common.bufferedhttp import http_connect
from swift.common.ring import Ring
from swift.common.daemon import Daemon
from swift.common.internal_client import InternalClient, UnexpectedResponse
from swift.common.utils import get_logger, dump_recon_cache, \
    normalize_timestamp, normalize_delete_at_timestamp

from swiftlifecyclemanagement.common.lifecycle import calc_nextDay


class ObjectRestorer(Daemon):
    """
    Daemon that queries the internal hidden expiring_objects_account to
    discover objects that need to be deleted.

    :param conf: The daemon configuration.
    """

    def __init__(self, conf):
        self.conf = conf
        self.container_ring = Ring('/etc/swift', ring_name='container')
        self.logger = get_logger(conf, log_route='object-restorer')
        self.interval = int(conf.get('interval') or 300)
        self.restoring_object_account = '.s3_restoring_objects'
        self.expiring_restored_account = '.s3_expiring_restored_objects'
        self.glacier_account_prefix = '.glacier_'
        self.todo_container = 'todo'
        self.restoring_container = 'restoring'
        conf_path = '/etc/swift/s3-object-restorer.conf'
        request_tries = int(conf.get('request_tries') or 3)
        self.glacier = self._init_glacier()
        self.glacier_tmpdir = conf.get('temp_path', '/var/cache/s3/')
        self.swift = InternalClient(conf_path,
                                    'Swift Object Restorer',
                                    request_tries)
        self.report_interval = int(conf.get('report_interval') or 300)
        self.report_first_time = self.report_last_time = time()
        self.report_objects = 0
        self.recon_cache_path = conf.get('recon_cache_path',
                                         '/var/cache/swift')
        self.rcache = join(self.recon_cache_path, 'object.recon')
        self.concurrency = int(conf.get('concurrency', 1))
        if self.concurrency < 1:
            raise ValueError("concurrency must be set to at least 1")
        self.processes = int(self.conf.get('processes', 0))
        self.process = int(self.conf.get('process', 0))

    def _init_glacier(self):
        con = Layer2()
        return con.get_vault('swift-s3-transition')

    def report(self, final=False):
        """
        Emits a log line report of the progress so far, or the final progress
        is final=True.

        :param final: Set to True for the last report once the expiration pass
                      has completed.
        """
        if final:
            elapsed = time() - self.report_first_time
            self.logger.info(_('Pass completed in %ds; %d objects restored') %
                             (elapsed, self.report_objects))
            dump_recon_cache({'object_expiration_pass': elapsed,
                              'expired_last_pass': self.report_objects},
                             self.rcache, self.logger)
        elif time() - self.report_last_time >= self.report_interval:
            elapsed = time() - self.report_first_time
            self.logger.info(_('Pass so far %ds; %d objects restored') %
                             (elapsed, self.report_objects))
            self.report_last_time = time()

    def run_once(self, *args, **kwargs):
        """
        Executes a single pass, looking for objects to expire.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon accepts processes and process keyword args.
                       These will override the values from the config file if
                       provided.
        """
        processes, process = self.get_process_values(kwargs)
        pool = GreenPool(self.concurrency)
        self.report_first_time = self.report_last_time = time()
        self.report_objects = 0
        try:
            self.logger.debug(_('Run begin'))

            for o in self.swift.iter_objects(self.restoring_object_account,
                                             self.todo_container):
                obj = o['name'].encode('utf8')
                if processes > 0:
                    obj_process = int(
                        hashlib.md5('%s/%s' % (self.todo_container, obj)).
                        hexdigest(), 16)
                    if obj_process % processes != process:
                        continue
                pool.spawn_n(self.start_object_restoring, obj)

            pool.waitall()

            for o in self.swift.iter_objects(self.restoring_object_account,
                                             self.restoring_container):
                obj = o['name'].encode('utf8')
                if processes > 0:
                    obj_process = int(
                        hashlib.md5('%s/%s' % (self.restoring_container, obj)).
                        hexdigest(), 16)
                    if obj_process % processes != process:
                        continue
                pool.spawn_n(self.check_object_restored, obj)

            pool.waitall()

            self.logger.debug(_('Run end'))
            self.report(final=True)
        except (Exception, Timeout) as e:
            self.logger.exception(_('Unhandled exception'))

    def run_forever(self, *args, **kwargs):
        """
        Executes passes forever, looking for objects to expire.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon has no additional keyword args.
        """
        sleep(random() * self.interval)
        while True:
            begin = time()
            try:
                self.run_once(*args, **kwargs)
            except (Exception, Timeout):
                self.logger.exception(_('Unhandled exception'))
            elapsed = time() - begin
            if elapsed < self.interval:
                sleep(random() * (self.interval - elapsed))

    def get_process_values(self, kwargs):
        """
        Gets the processes, process from the kwargs if those values exist.

        Otherwise, return processes, process set in the config file.

        :param kwargs: Keyword args passed into the run_forever(), run_once()
                       methods.  They have values specified on the command
                       line when the daemon is run.
        """
        if kwargs.get('processes') is not None:
            processes = int(kwargs['processes'])
        else:
            processes = self.processes

        if kwargs.get('process') is not None:
            process = int(kwargs['process'])
        else:
            process = self.process

        if process < 0:
            raise ValueError(
                'process must be an integer greater than or equal to 0')

        if processes < 0:
            raise ValueError(
                'processes must be an integer greater than or equal to 0')

        if processes and process >= processes:
            raise ValueError(
                'process must be less than or equal to processes')

        return processes, process

    def start_object_restoring(self, obj):
        start_time = time()
        try:
            # OBJECT 형태 a/c/o-archiveid
            actual_obj = obj
            account, container, obj = actual_obj.split('/', 2)
            archiveId = self.get_archiveid(account, container, obj)
            jobId = self.glacier.retrieve_archive(archiveId).id
            restoring_obj = '%s-%s' % (actual_obj, jobId)

            meta_prefix = 'X-Object-Meta'
            meta = self.swift.get_object_metadata(account, container, obj,
                                                  metadata_prefix=meta_prefix)
            meta = {'X-Object-Meta' + key: value for key, value in
                    meta.iteritems()}
            self.update_action_hidden(self.restoring_object_account,
                                      self.restoring_container,
                                      restoring_obj, metadata=meta)

            self.swift.delete_object(self.restoring_object_account,
                                     self.todo_container, obj)
            self.report_objects += 1
            self.logger.increment('objects')
        except (Exception, Timeout) as err:
            self.logger.increment('errors')
            self.logger.exception(
                _('Exception while restoring object %s. %s') %
                (obj, str(err)))
        self.logger.timing_since('timing', start_time)
        self.report()

    def get_archiveid(self, account, container, obj):
        glacier_account = '%s%s' % (self.glacier_account_prefix, account)

        hobj = None
        for o in self.swift.iter_objects(glacier_account, container):
            hobj = o['name']
            aobj = hobj.split('-', 2)[0]
            if aobj == obj:
                break
        return hobj.split('-', 1)[1]

    def check_object_restored(self, restoring_object):
        actual_obj, jobId = restoring_object.split('-', 1)
        try:
            path = '/v1/%s' % actual_obj
            resp = self.swift.make_request('GET', path, {}, (2, 4,))
            if resp.status_int == 404:
                raise Exception('Object Not Found: %s' % actual_obj)

            job = self.glacier.get_job(job_id=jobId)
            if not job.completed:
                return
            self.complete_restore(actual_obj, job)
        except Exception as e:
            # Job ID가 만료될 경우 다시 restore 를 시도한다.
            if not e.message.startswith('Object Not Found:'):
                self.start_object_restoring(actual_obj)
            self.logger.info(e)

        self.swift.delete_object(self.restoring_object_account,
                                 self.restoring_container, restoring_object)

    def complete_restore(self, actual_obj, job):
        tmppath = tempfile.NamedTemporaryFile(bufsize=0, delete=False,
                                              dir=self.glacier_tmpdir).name
        try:
            job.download_to_file(filename=tmppath)

            prefix = 'X-Object-Meta'
            a, c, o = actual_obj.split('/', 2)
            metadata = self.swift.get_object_metadata(a, c, o,
                                                      metadata_prefix=prefix)
            metadata = {'X-Object-Meta' + key: value for key, value in metadata
            .iteritems()}
            days = int(metadata['X-Object-Meta-s3-restore-expire-days'])
            exp_time = normalize_delete_at_timestamp(calc_nextDay(time()) +
                                                     (days - 1) * 86400)

            # send restored object to proxy server
            path = '/v1/%s' % actual_obj
            metadata['X-Object-Meta-S3-Restored'] = True
            exp_date = strftime("%a, %d %b %Y %H:%M:%S GMT",
                                gmtime(float(exp_time)))

            metadata['X-Object-Meta-s3-restore'] = 'ongoing-request="false" ' \
                                                   'expiry-date=%s' % exp_date
            metadata['Content-Length'] = os.path.getsize(tmppath)
            del metadata['X-Object-Meta-s3-restore-expire-days']

            obj_body = open(tmppath, 'r')
            self.swift.make_request('PUT', path, metadata, (2,),
                                    body_file=obj_body)

            # Add to .s3_expiring_restored_objects
            self.update_action_hidden(self.expiring_restored_account,
                                      exp_time, actual_obj)
            obj_body.close()
        except UnexpectedResponse as e:
            if e.resp.status_int == 404:
                self.logger.error('Restoring object not found - %s' %
                                  actual_obj)
        except Exception as e:
            self.logger.debug(e)
        finally:
            os.remove(tmppath)

    def compute_obj_md5(self, obj):
        etag = hashlib.md5()
        etag.update(obj)
        etag = etag.hexdigest()
        return etag

    def update_action_hidden(self, account, container, obj, metadata=None):
        hidden_path = '/%s/%s/%s' % (account, container, obj)
        part, nodes = self.container_ring.get_nodes(account, container)
        for node in nodes:
            ip = node['ip']
            port = node['port']
            dev = node['device']
            action_headers = dict()
            action_headers['user-agent'] = 'restore-daemon'
            action_headers['X-Timestamp'] = normalize_timestamp(time())
            action_headers['referer'] = 'restore-daemon'
            action_headers['x-size'] = '0'
            action_headers['x-content-type'] = "text/plain"
            action_headers['x-etag'] = 'd41d8cd98f00b204e9800998ecf8427e'

            if metadata:
                action_headers.update(metadata)

            conn = http_connect(ip, port, dev, part, 'PUT', hidden_path,
                                action_headers)
            response = conn.getresponse()
            response.read()
