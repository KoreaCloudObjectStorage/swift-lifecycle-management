import urllib
import ast
import calendar
from datetime import datetime
from operator import itemgetter
from random import random
from time import time
from os.path import join
from swift import gettext_ as _
import hashlib

from eventlet import sleep, Timeout
from eventlet.greenpool import GreenPool

from swift.common.daemon import Daemon
from swift.common.internal_client import InternalClient
from swift.common.utils import get_logger, dump_recon_cache
from swift.common.http import HTTP_NOT_FOUND, HTTP_CONFLICT, \
    HTTP_PRECONDITION_FAILED

class ObjectExpirer(Daemon):

    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf, log_route='object-expirer')
        self.interval = int(conf.get('interval') or 300)
        self.expiring_objects_account = \
            (conf.get('auto_create_account_prefix') or '.') + \
            (conf.get('expiring_objects_account_name') or 's3_expiring_objects')
        conf_path = conf.get('__file__') or '/etc/swift/s3-object-expirer.conf'
        request_tries = int(conf.get('request_tries') or 3)
        self.swift = InternalClient(conf_path,
                                    'Swift Object Expirer',
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

    def report(self, final=False):
        """
        Emits a log line report of the progress so far, or the final progress
        is final=True.

        :param final: Set to True for the last report once the expiration pass
                      has completed.
        """
        if final:
            elapsed = time() - self.report_first_time
            self.logger.info(_('Pass completed in %ds; %d objects expired') %
                             (elapsed, self.report_objects))
            dump_recon_cache({'object_expiration_pass': elapsed,
                              'expired_last_pass': self.report_objects},
                             self.rcache, self.logger)
        elif time() - self.report_last_time >= self.report_interval:
            elapsed = time() - self.report_first_time
            self.logger.info(_('Pass so far %ds; %d objects expired') %
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
        containers_to_delete = []
        self.report_first_time = self.report_last_time = time()
        self.report_objects = 0
        try:
            self.logger.debug(_('Run begin'))
            containers, objects = \
                self.swift.get_account_info(self.expiring_objects_account)
            self.logger.info(_('Pass beginning; %s possible containers; %s '
                               'possible objects') % (containers, objects))
            for c in self.swift.iter_containers(self.expiring_objects_account):
                container = c['name']
                timestamp = int(container)
                if timestamp > int(time()):
                    break
                containers_to_delete.append(container)
                for o in self.swift.iter_objects(self.expiring_objects_account,
                                                 container):
                    obj = o['name'].encode('utf8')
                    if processes > 0:
                        obj_process = int(
                            hashlib.md5('%s/%s' % (container, obj)).
                            hexdigest(), 16)
                        if obj_process % processes != process:
                            continue

                    pool.spawn_n(
                        self.delete_object, obj, timestamp,
                        container, obj)
            pool.waitall()
            for container in containers_to_delete:
                try:
                    self.swift.delete_container(
                        self.expiring_objects_account,
                        container,
                        acceptable_statuses=(2, HTTP_NOT_FOUND, HTTP_CONFLICT))
                except (Exception, Timeout) as err:
                    self.logger.exception(
                        _('Exception while deleting container %s %s') %
                        (container, str(err)))
            self.logger.debug(_('Run end'))
            self.report(final=True)
        except (Exception, Timeout):
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

    def delete_object(self, actual_obj, timestamp, container, obj):
        start_time = time()
        try:
            # GET Container's Lifecycle
            actual_account, actual_container, actual_object = actual_obj.split('/', 2)
            actual_container_path = '/v1/%s/%s' % (actual_account, actual_container)

            resp = self.swift.make_request('HEAD', actual_container_path, {}, (2,))
            lifecycle = ast.literal_eval(resp.headers['X-Container-Sysmeta-S3-Lifecycle-Configuration'])

            prefixMap = map(itemgetter('Prefix'), lifecycle)
            prefixIndex = [prefixMap.index(i) for i in prefixMap if actual_object.startswith(i)]
            container_lifecycle = lifecycle[prefixIndex[0]] if len(prefixIndex) >= 1 else None

            # GET Object Lifecycle
            actual_obj_path = '/v1/%s' % actual_obj
            resp = self.swift.make_request('HEAD', actual_obj_path, {}, (2,))

            object_lifecycle = resp.headers['X-Object-Meta-Rule-Id'] if 'X-Object-Meta-Rule-Id' in resp.headers \
                                                                    else None

            delete_actual_flg = False
            if container_lifecycle:
                container_timestamp = dict()
                for key in container_lifecycle:
                    if key in ('Expiration', 'Transition'):
                        container_timestamp[key] = container_lifecycle[key][key.lower()+'-last-modified']

                if object_lifecycle:
                    validationFlg = True
                    object_timestamp = dict()

                    for key, value in resp.headers.iteritems():
                        if key in ('X-Object-Meta-Expiration-Last-Modified',
                                 'X-Object-Meta-Transition-Last-Modified'):
                            object_timestamp[key.split('-', 4)[3]] = value

                    for key, value in container_timestamp.iteritems() if validationFlg else {}.iteritems():
                        if key in object_timestamp:
                            if value == object_timestamp[key]:
                                delete_actual_flg = True
                            else:
                                delete_actual_flg = False

            if delete_actual_flg:
                self.delete_actual_object(actual_obj, timestamp)

            self.swift.delete_object(self.expiring_objects_account,
                                     container, obj)
            self.report_objects += 1
            self.logger.increment('objects')
        except (Exception, Timeout) as err:
            self.logger.increment('errors')
            self.logger.exception(
                _('Exception while deleting object %s %s %s') %
                (container, obj, str(err)))
        self.logger.timing_since('timing', start_time)
        self.report()

    def delete_actual_object(self, actual_obj, timestamp):
        """
        Deletes the end-user object indicated by the actual object name given
        '<account>/<container>/<object>' if and only if the X-Delete-At value
        of the object is exactly the timestamp given.

        :param actual_obj: The name of the end-user object to delete:
                           '<account>/<container>/<object>'
        :param timestamp: The timestamp the X-Delete-At value must match to
                          perform the actual delete.
        """
        path = '/v1/' + urllib.quote(actual_obj.lstrip('/'))
        self.swift.make_request('DELETE', path,
                                {},
                                (2, HTTP_NOT_FOUND, HTTP_PRECONDITION_FAILED))
