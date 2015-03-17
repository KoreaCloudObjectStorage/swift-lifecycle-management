import urllib
import hashlib
from random import random
from time import time
from os.path import join

from boto.glacier.layer2 import Layer2
from eventlet import sleep, Timeout
from eventlet.greenpool import GreenPool

from swift import gettext_ as _
from swift.common.daemon import Daemon
from swift.common.internal_client import InternalClient
from swift.common.utils import get_logger, dump_recon_cache
from swift.common.http import HTTP_NOT_FOUND, HTTP_CONFLICT

from swiftlifecyclemanagement.common.lifecycle import Lifecycle, \
    LIFECYCLE_OK, calc_when_actions_do, DISABLED_TRANSITION, SKIP_THIS_OBJECT
from swiftlifecyclemanagement.common.utils import gmt_to_timestamp, \
    get_objects_by_prefix, get_glacier_objname_from_hidden_object, \
    get_glacier_key_from_hidden_object


class ObjectExpirer(Daemon):
    def __init__(self, conf):
        super(ObjectExpirer, self).__init__(conf)
        self.conf = conf
        self.logger = get_logger(conf, log_route='s3-object-expirer')
        self.logger.set_statsd_prefix('s3-object-expirer')
        self.interval = int(conf.get('interval') or 300)
        self.s3_expiring_objects_account = \
            (conf.get('auto_create_account_prefix') or '.') + \
            (conf.get('expiring_objects_account_name') or
             's3_expiring_objects')
        conf_path = conf.get('__file__') or '/etc/swift/s3-object-expirer.conf'
        request_tries = int(conf.get('request_tries') or 3)
        self.swift = InternalClient(conf_path,
                                    'Swift Object Expirer',
                                    request_tries)
        self.glacier = self._init_glacier()
        self.glacier_account_prefix = '.glacier_'
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
        con = Layer2(region_name='ap-northeast-1')
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
                self.swift.get_account_info(self.s3_expiring_objects_account)
            self.logger.info(_('Pass beginning; %s possible containers; %s '
                               'possible objects') % (containers, objects))

            for c in self.swift.iter_containers(self.
                                                s3_expiring_objects_account):
                container = c['name']
                timestamp = int(container)
                if timestamp > int(time()):
                    break
                containers_to_delete.append(container)
                for o in self.swift.iter_objects(self
                                                 .s3_expiring_objects_account,
                                                 container):
                    obj = o['name'].encode('utf8')
                    if processes > 0:
                        obj_process = int(
                            hashlib.md5('%s/%s' % (container, obj)).
                            hexdigest(), 16)
                        if obj_process % processes != process:
                            continue

                    pool.spawn_n(self.delete_object, container, obj)
            pool.waitall()
            for container in containers_to_delete:
                try:
                    self.swift.delete_container(
                        self.s3_expiring_objects_account,
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

    def delete_object(self, hidden_container, obj):
        start_time = time()
        try:
            account, container, object = obj.split('/', 2)
            lifecycle = Lifecycle(account, container, object,
                                  swift_client=self.swift)
            # object , container 404 일 경우.. 에러터짐
            object_header = lifecycle.object.headers
            object_rule = lifecycle.get_object_rule_by_action('Expiration')
            last_modified = gmt_to_timestamp(object_header['Last-Modified'])

            validation_flg = lifecycle.object_lifecycle_validation()
            if (validation_flg == LIFECYCLE_OK) or \
                    (validation_flg == DISABLED_TRANSITION):
                times = calc_when_actions_do(object_rule, last_modified)
                actual_expire_time = int(times['Expiration'])
                if actual_expire_time == int(hidden_container):
                    self.delete_actual_object(obj)
                if lifecycle.get_s3_storage_class() == 'GLACIER':
                    self.delete_glacier_object(obj)
                self.report_objects += 1
                self.logger.increment('objects')
                self.swift.delete_object(self.s3_expiring_objects_account,
                                         hidden_container, obj)
        except (Exception, Timeout) as err:
            self.logger.increment('errors')
            self.logger.exception(
                _('Exception while deleting object %s %s %s') %
                (hidden_container, obj, str(err)))

        self.logger.timing_since('timing', start_time)
        self.report()

    def delete_glacier_object(self, obj):
        account, container, prefix = obj.split('/', 2)
        glacier_hidden_account = self.glacier_account_prefix + account
        objs = get_objects_by_prefix(glacier_hidden_account, container, prefix,
                                     swift_client=self.swift)

        glacier_obj = None
        for o in objs:
            name = get_glacier_objname_from_hidden_object(o)
            if name == prefix:
                glacier_obj = o
                break

        glacier_archive_id = get_glacier_key_from_hidden_object(glacier_obj)
        self.glacier.delete_archive(glacier_archive_id)
        self.swift.delete_object(glacier_hidden_account, container,
                                 glacier_obj)

    def delete_actual_object(self, obj):
        """
        Deletes the end-user object indicated by the actual object name given
        '<account>/<container>/<object>' if and only if the X-Delete-At value
        of the object is exactly the timestamp given.

        :param obj: The name of the end-user object to delete:
                           '<account>/<container>/<object>'
        """
        path = '/v1/' + urllib.quote(obj.lstrip('/'))
        self.swift.make_request('DELETE', path,
                                {}, (2, HTTP_NOT_FOUND))
