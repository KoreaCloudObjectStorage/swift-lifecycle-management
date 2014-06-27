import urllib
import ast
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
        super(ObjectExpirer, self).__init__(conf)
        self.conf = conf
        self.logger = get_logger(conf, log_route='s3-object-expirer')
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

    def delete_object(self, container, obj):
        start_time = time()
        try:
            validation_flg = self.validate_object_lifecycle(obj)

            if validation_flg:
                self.delete_actual_object(obj)

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

    def get_container_lifecycle(self, obj_path):
        account, container, prefix = self.split_object_path(obj_path)

        path = '/v1/%s/%s' % (account, container)
        resp = self.swift.make_request('HEAD', path, {}, (2, 4))

        if resp.status_int is HTTP_NOT_FOUND:
            return None

        lc_sysmeta = 'X-Container-Sysmeta-S3-Lifecycle-Configuration'

        if lc_sysmeta not in resp.headers:
            return None

        rule_list = ast.literal_eval(resp.headers[lc_sysmeta])
        prefixMap = map(itemgetter('Prefix'), rule_list)

        prefixIndex = -1
        for p in prefixMap:
            if prefix.startswith(p):
                prefixIndex = prefixMap.index(p)
                break

        if prefixIndex < 0:
            return None

        rule = rule_list[prefixIndex]

        lifecycle = dict()
        lifecycle['ID'] = rule['ID']
        for key in rule:
            if key in ('Expiration', 'Transition'):
                lifecycle[key] = rule[key][key.lower()+'-last-modified']

        return lifecycle

    def get_object_lifecycle_rule_id(self, obj_path):
        account, container, obj = self.split_object_path(obj_path)

        path = '/v1/%s/%s/%s' % (account, container, obj)
        resp = self.swift.make_request('HEAD', path, {}, (2,))

        if resp.status_int is HTTP_NOT_FOUND:
            return None

        if 'X-Object-Meta-Rule-Id' not in resp.headers:
            return None

        lifecycle = dict()
        lifecycle['ID'] = resp.headers['X-Object-Meta-Rule-Id']
        for key, value in resp.headers.iteritems():
            if key in ('X-Object-Meta-Expiration-Last-Modified',
                       'X-Object-Meta-Transition-Last-Modified'):
                lifecycle[key.split('-', 4)[3]] = value

        return lifecycle

    def split_object_path(self, obj_path):
        return obj_path.split('/', 2)

    def validate_object_lifecycle(self, obj):
        # GET Container's Lifecycle
        container_lifecycle = self.get_container_lifecycle(obj)

        if not container_lifecycle:
            return False

        # GET Object Lifecycle
        object_lifecycle = self.get_object_lifecycle_rule_id(obj)

        delete_actual_flg = False
        if not object_lifecycle:
            return False

        for key in ('Expiration', 'Transition'):
            if key not in object_lifecycle and \
               key not in container_lifecycle:
                return False

            if container_lifecycle[key] == object_lifecycle[key]:
                delete_actual_flg = True
            else:
                delete_actual_flg = False

        return delete_actual_flg