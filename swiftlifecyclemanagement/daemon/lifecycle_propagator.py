# -*- coding: utf-8 -*-
import ast
from swift.common.http import is_success
from time import time

from random import random
from swift.common.bufferedhttp import http_connect
from swift.common.ring import Ring
from os.path import join
from swift import gettext_ as _
import hashlib

from eventlet import sleep, Timeout
from eventlet.greenpool import GreenPool

from swift.common.daemon import Daemon
from swift.common.internal_client import InternalClient
from swift.common.utils import get_logger, dump_recon_cache, \
    normalize_timestamp

from swiftlifecyclemanagement.common.lifecycle import \
    CONTAINER_LIFECYCLE_SYSMETA, Object, \
    OBJECT_LIFECYCLE_NOT_EXIST, LIFECYCLE_OK, LIFECYCLE_ERROR, \
    CONTAINER_LIFECYCLE_IS_UPDATED, calc_when_actions_do
from swiftlifecyclemanagement.common.utils import gmt_to_timestamp
from swiftlifecyclemanagement.middleware.lifecycle.utils import make_object_metadata_from_rule


class LifecyclePropagator(Daemon):
    def __init__(self, conf):
        super(LifecyclePropagator, self).__init__(conf)
        self.conf = conf
        self.logger = get_logger(conf, log_route='lifecycle-propagator')
        self.interval = int(conf.get('interval') or 300)
        self.s3_accounts = '.s3_accounts'
        self.container_ring = Ring('/etc/swift', ring_name='container')
        self.hidden_accounts = {'expiration': '.s3_expiring_objects',
                                'transition': '.s3_transitioning_objects'}
        conf_path = conf.get(
            '__file__') or '/etc/swift/s3-lifecycle-propagator.conf'
        request_tries = int(conf.get('request_tries') or 3)
        self.swift = InternalClient(conf_path, 'Swift Lifecycle Propagator',
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

    def __call__(self):
        super.__call__(self)

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
                             self.rcache,
                             self.logger)
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
        self.report_first_time = self.report_last_time = time()
        self.report_objects = 0
        try:
            self.logger.debug(_('Run begin'))
            for c in self.swift.iter_containers(self.s3_accounts):
                container = c['name']
                for o in self.swift.iter_objects(self.s3_accounts, container):
                    obj = o['name']
                    if processes > 0:
                        container_process = int(hashlib.md5(
                            '%s/%s' % (container, obj)).hexdigest(), 16)
                        if container_process % processes != process:
                            continue
                    pool.spawn_n(self.propagate_container, container, obj)
            pool.waitall()
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

    def propagate_container(self, account, container):
        lifecycle = self.get_container_lifecycle(account, container)
        # 만약 Container 에 LC가 없으면, hidden account 에서 삭제
        if not lifecycle:
            self.swift.delete_object(self.s3_accounts, account, container)

        rules = self.get_not_propagated_rules(lifecycle)
        for rule in rules:
            propagated = self.propagate_rule(account, container, rule)
            if not propagated:
                continue
            self.set_rule_propagated(rule)

        # Update Container lifecycle
        cpath = '/v1/%s/%s' % (account, container)
        self.swift.make_request('POST', cpath, {CONTAINER_LIFECYCLE_SYSMETA:
                                rules}, (2,))

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

    def propagate_rule(self, account, container, rule):
        prefix = rule['Prefix']
        objects = self.get_objects_by_prefix(account, container, prefix)
        propagated = True
        for o in objects:
            lc = Object(account, container, o, swift_client=self.swift)

            validation_flg = lc.object_lifecycle_validation()
            if validation_flg is LIFECYCLE_OK:
                continue

            if validation_flg is LIFECYCLE_ERROR:
                self.logger.error(_('Lifecycle ERROR'))
                continue
            if validation_flg not in (OBJECT_LIFECYCLE_NOT_EXIST,
                                      CONTAINER_LIFECYCLE_IS_UPDATED):
                continue

            metadata = make_object_metadata_from_rule(rule)
            is_updated = self.update_object_metadata(account, container,
                                                     o, metadata)
            # update가 안되었으면, propagated가 안된 것으로 처리
            if not is_success(is_updated):
                propagated = False

            obj_last_modi = lc.o_lifecycle.headers['Last-Modified']
            obj_last_modi = gmt_to_timestamp(obj_last_modi)
            actionList = calc_when_actions_do(rule, obj_last_modi)
            for action, at_time in actionList.iteritems():
                self.update_action_hidden(hidden={
                    'account': self.hidden_accounts[action.lower()],
                    'container': at_time
                }, orig={
                    'account': account,
                    'container': container,
                    'object': o
                })
        return propagated

    def get_container_lifecycle(self, account, container):
        path = '/v1/%s/%s' % (account, container)
        resp = self.swift.make_request('HEAD', path, {}, (2, 4))

        if CONTAINER_LIFECYCLE_SYSMETA not in resp.headers:
            return None

        return ast.literal_eval(resp.headers[CONTAINER_LIFECYCLE_SYSMETA])

    def get_not_propagated_rules(self, lifecycle):
        result = list()
        to_append = False
        for rule in lifecycle:
            for key, value in rule.iteritems():
                if type(value) is not dict:
                    continue
                for subkey, subvalue in value.iteritems():
                    if not subkey.endswith('-propagated'):
                        continue
                    if not to_append and subvalue == '0':
                        to_append = True
            if to_append:
                result.append(rule)
            to_append = False
        return result

    def get_objects_by_prefix(self, account, container, prefix):
        iter_objs = self.swift.iter_objects(account, container, marker=prefix)
        objs = list()

        for o in iter_objs:
            objs.append(o['name'])
        return objs

    def set_rule_propagated(self, rule):
        for key, value in rule.iteritems():
            if type(value) is not dict:
                continue
            for subkey, subvalue in value.iteritems():
                if not subkey.endswith('-propagated'):
                    continue
                rule[key][subkey] = '1'
                break

    def update_object_metadata(self, account, container, obj, headers):
        path = '/v1/%s/%s/%s' % (account, container, obj)
        resp = self.swift.make_request('POST', path, headers, (2, 4))
        return resp.status_int

    def update_action_hidden(self, hidden, orig):
        hidden_obj = '%s/%s/%s' % (orig['account'], orig['container'],
                                   orig['object'])
        hidden_path = '/%s/%s/%s' % (hidden['account'], hidden['container'],
                                     hidden_obj)
        part, nodes = self.container_ring.get_nodes(hidden['account'],
                                                    str(hidden['container']))
        for node in nodes:
            ip = node['ip']
            port = node['port']
            dev = node['device']
            action_headers = dict()
            action_headers['user-agent'] = 'lifecycle'
            action_headers['X-Timestamp'] = normalize_timestamp(time())
            action_headers['referer'] = 'propagate-daemon'
            action_headers['x-size'] = '0'
            action_headers['x-content-type'] = "text/plain"
            action_headers['x-etag'] = 'd41d8cd98f00b204e9800998ecf8427e'

            conn = http_connect(ip, port, dev, part, 'PUT', hidden_path,
                                action_headers)
            response = conn.getresponse()
            response.read()