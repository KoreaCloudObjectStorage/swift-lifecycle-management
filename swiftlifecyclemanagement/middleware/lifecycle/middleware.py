# -*- coding: utf-8 -*-
import time
import xml.etree.ElementTree as ET
import urlparse
from base64 import encodestring as encodebytes
from boto.glacier.layer2 import Layer2
from urllib2 import unquote
from operator import itemgetter
from copy import copy
from hashlib import md5

from swift.common.swob import Request, Response
from swift.common.utils import get_logger, split_path, \
    normalize_timestamp
from swift.common.wsgi import WSGIContext
from swift.common.http import HTTP_NO_CONTENT, HTTP_NOT_FOUND, HTTP_OK, \
    HTTP_FORBIDDEN, HTTP_BAD_REQUEST, HTTP_CREATED
from swift.common.ring import Ring
from swift.common.bufferedhttp import http_connect
from swift.common.request_helpers import is_user_meta

from exceptions import LifecycleConfigException
from swiftlifecyclemanagement.common.utils import gmt_to_timestamp, \
    get_objects_by_prefix, get_glacier_key_from_hidden_object, \
    get_glacier_objname_from_hidden_object
from utils import xml_to_list, lifecycle_to_xml, \
    updateLifecycleMetadata, check_lifecycle_validation, \
    make_object_metadata_from_rule
from swiftlifecyclemanagement.common.lifecycle import Lifecycle, \
    CONTAINER_LIFECYCLE_NOT_EXIST, LIFECYCLE_RESPONSE_HEADER, \
    OBJECT_LIFECYCLE_NOT_EXIST, CONTAINER_LIFECYCLE_IS_UPDATED, \
    LIFECYCLE_ERROR, calc_when_actions_do, \
    LIFECYCLE_NOT_EXIST, ContainerLifecycle, ObjectLifecycle, \
    OBJECT_LIFECYCLE_META, DISABLED_BOTH, DISABLED_EXPIRATION


def get_err_response(err):
    """
    Given an HTTP response code, create a properly formatted xml error response

    :param code: error code
    :returns: webob.response object
    """

    resp = Response(content_type='text/xml')
    resp.status = err['status']
    xml_code = '' if 'code' not in err else '<Code>%s</Code>' % err['code']
    xml_msg = '' if 'msg' not in err else '<Message>%s</Message>' % err['msg']
    xml_arg_value = '' if 'arg_value' not in err else '<ArgumentValue>%s</ArgumentValue>' % err['arg_value']
    xml_arg_name = '' if 'arg_name' not in err else '<ArgumentName>%s</ArgumentName>' % err['arg_name']
    resp.body = """<?xml version="1.0" encoding="UTF-8"?>
                   <Error>%s%s%s%s</Error>""" \
                % (xml_code, xml_msg, xml_arg_value, xml_arg_name)
    resp.headers = {LIFECYCLE_RESPONSE_HEADER: True}
    return resp


class ObjectController(WSGIContext):
    def __init__(self, app, logger, account, container_name, object_name):
        WSGIContext.__init__(self, app)
        self.account = account
        self.container = container_name
        self.object = object_name
        self.hidden_accounts = {'expiration': '.s3_expiring_objects',
                                'transition': '.s3_transitioning_objects'}
        self.container_ring = Ring('/etc/swift', ring_name='container')
        self.logger = logger

    def GETorHEAD(self, env, start_response):
        lifecycle = Lifecycle(self.account, self.container, self.object,
                              env=env, app=self.app)

        http_status = lifecycle.object.status
        headers = lifecycle.object.headers
        object_s3_storage_class = lifecycle.get_s3_storage_class()

        if http_status is not HTTP_OK:
            return Response(status=http_status)

        last_modified = gmt_to_timestamp(headers['Last-Modified'])

        is_glacier = False
        if object_s3_storage_class == 'GLACIER':
            is_glacier = True

        restoring = headers.get('X-Object-Meta-S3-Restore')
        if restoring and restoring != 'ongoing-request="true"':
            is_glacier = False

        # Glacier로 Transition 된 Object 일 경우
        if is_glacier:
            resp = Response(headers=headers)
            resp.status = HTTP_FORBIDDEN
            resp.headers[LIFECYCLE_RESPONSE_HEADER] = True

            if env['REQUEST_METHOD'] == 'GET':
                body = '<Error>\n' \
                       '<Code>InvalidObjectState</Code>\n' \
                       '<Message>The operation is not valid ' \
                       'for the object\'s storage class</Message>\n' \
                       '</Error>\n'
                resp.body = body
                resp.content_type = 'application/xml'
            elif env['REQUEST_METHOD'] == 'HEAD':
                resp.content_length = headers[
                    'X-Object-Meta-S3-Content-Length']
                resp.etag = headers['X-Object-Meta-S3-ETag']
                resp.status = HTTP_OK

            return resp

        obj_lc_status = lifecycle.object_lifecycle_validation()

        if obj_lc_status == CONTAINER_LIFECYCLE_NOT_EXIST:
            # Setting Object's Lifecycle to empty
            req = Request(copy(env))
            req.method = 'POST'
            for h in copy(headers):
                if not is_user_meta('object', h):
                    del headers[h]
                if h.startswith(OBJECT_LIFECYCLE_META['Expiration']) or \
                        h.startswith(OBJECT_LIFECYCLE_META['Transition']):
                    del headers[h]
            req.headers.update(headers)
            req.get_response(self.app)

        elif obj_lc_status in (OBJECT_LIFECYCLE_NOT_EXIST,
                               CONTAINER_LIFECYCLE_IS_UPDATED):
            # Make new object metadata
            object_rules = lifecycle.container.get_rules_by_object_name(
                self.object)
            new_header = dict()

            for key, value in headers.iteritems():
                _key = key.lower()
                if not _key.startswith('x-object-meta'):
                    continue
                new_header[key] = value

            # new_header 에 기존 object 의 metadata 도 넣기
            for rule in object_rules:
                h = make_object_metadata_from_rule(rule)
                new_header.update(h)
                actionList = calc_when_actions_do(rule, last_modified)

                #Update Hidden Information
                for key in actionList:
                    self.hidden_update(hidden={
                        'account': self.hidden_accounts[key.lower()],
                        'container': actionList[key]
                    }, orig={
                        'account': self.account,
                        'container': self.container,
                        'object': self.object
                    })

            # Update object meta to container LC
            req = Request(copy(env))
            req.method = 'POST'
            req.headers.update(new_header)
            req.get_response(self.app)
        elif obj_lc_status == LIFECYCLE_ERROR:
            return Response(status=HTTP_NOT_FOUND)

        req = Request(env)
        resp = req.get_response(self.app)

        if obj_lc_status in (LIFECYCLE_NOT_EXIST,
                             CONTAINER_LIFECYCLE_NOT_EXIST,
                             DISABLED_EXPIRATION, DISABLED_BOTH):
            return resp

        lifecycle.reload()
        object_lifecycle = lifecycle.get_object_rule_by_action('Expiration')
        if object_lifecycle:
            actions = calc_when_actions_do(object_lifecycle, last_modified)
            expire_at = actions['Expiration']
            expire_date = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                        time.gmtime(float(expire_at)))
            resp.headers['X-Amz-Expiration'] = 'expiry-date="%s",' \
                                               'rule-id="%s"' % \
                                               (expire_date,
                                                object_lifecycle['ID'])
        return resp

    def GET(self, env, start_response):
        return self.GETorHEAD(env, start_response)

    def DELETE(self, env, start_response):
        lc = ObjectLifecycle(self.account, self.container, self.object,
                             env=env, app=self.app)

        if lc.get_s3_storage_class() == 'GLACIER':
            self.delete_glacier_object()

        return self.app

    def HEAD(self, env, start_response):
        return self.GETorHEAD(env, start_response)

    def POST(self, env, start_response):
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        if 'restore' in args:
            return self.restore_object(env)
        return Response(status=HTTP_BAD_REQUEST)

    def PUT(self, env, start_response):
        lc = Lifecycle(self.account, self.container, self.object, env=env,
                       app=self.app)
        container_lc = lc.container

        is_glacier = lc.get_s3_storage_class()

        if is_glacier == 'GLACIER':
            self.delete_glacier_object()

        lifecycle = container_lc.get_lifecycle()
        if not lifecycle:
            return self.app

        if 'HTTP_X_STATIC_LARGE_OBJECT' in env:
            return self.app

        rules = container_lc.get_rules_by_object_name(self.object)
        rule_header = dict()

        for rule in rules:
            headers = make_object_metadata_from_rule(rule)
            rule_header.update(headers)

            actionList = calc_when_actions_do(rule, time.time())
            if actionList:
                for action, at_time in actionList.iteritems():
                    hidden_account = self.hidden_accounts[action.lower()]
                    action_at = at_time
                    self.hidden_update(hidden=dict({
                        'account': hidden_account,
                        'container': action_at
                    }), orig=dict({
                        'account': self.account,
                        'container': self.container,
                        'object': self.object
                    }))

        req = Request(env)
        req.headers.update(rule_header)
        return req.get_response(self.app)

    def hidden_update(self, hidden, orig, method='PUT'):
        if type(orig) is dict:
            hidden_obj = '%s/%s/%s' % (orig['account'], orig['container'],
                                       orig['object'])
        else:
            hidden_obj = orig

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
            action_headers['X-Timestamp'] = normalize_timestamp(time.time())
            action_headers['referer'] = 'lifecycle-middleware'
            action_headers['x-size'] = '0'
            action_headers['x-content-type'] = "text/plain"
            action_headers['x-etag'] = 'd41d8cd98f00b204e9800998ecf8427e'

            conn = http_connect(ip, port, dev, part, method, hidden_path,
                                action_headers)
            response = conn.getresponse()
            response.read()

    def delete_glacier_object(self):
        objs = get_objects_by_prefix('.glacier_%s' % self.account,
                                     self.container, self.object, app=self.app)
        glacier_obj = None
        for o in objs:
            name = get_glacier_objname_from_hidden_object(o)
            if name == self.object:
                glacier_obj = o
                break

        if not glacier_obj:
            return

        archive_id = get_glacier_key_from_hidden_object(glacier_obj)
        try:
            region = 'ap-northeast-1'
            vault = Layer2(region_name=region).get_vault('swift-s3-transition')
            vault.delete_archive(archive_id)
            self.hidden_update(
                hidden={'account': '.glacier_' + self.account,
                        'container': self.container},
                orig=glacier_obj, method='DELETE')
        except Exception as e:
            # Print Error Log
            raise e

    def restore_object(self, env):
        req = Request(env)

        # Check If already restoring
        is_restoring, headers = self.is_already_restoring(env)
        if is_restoring:
            return Response(status=HTTP_BAD_REQUEST, body='Already Restoring')

        # Get Restored object expire days from xml
        body = req.body
        days = self._get_days_from_restore_xml(body)
        # Set Metadata
        expire_meta = 'X-Object-Meta-S3-Restore-Expire-Days'
        hidden_obj = '%s/%s/%s' % (self.account, self.container, self.object)
        self.start_restoring('.s3_restoring_objects', 'todo', hidden_obj)

        # Update Object Meta to restoring
        restore_meta = {
            'X-Object-Meta-S3-Restore': 'ongoing-request="true"',
            expire_meta: days
        }

        # GET exist object metadata
        restore_meta.update(val for val in headers.iteritems()
                            if is_user_meta('object', val[0]))

        req.headers.update(restore_meta)
        return req.get_response(self.app)

    def is_already_restoring(self, env):
        req = Request(copy(env))
        req.method = 'HEAD'
        resp = req.get_response(self.app)

        existed = False
        if 'X-Object-Meta-S3-Restore' in resp.headers:
            existed = True
        return existed, resp.headers

    def _get_days_from_restore_xml(self, body):
        root = ET.fromstring(body)
        ns = 'http://s3.amazonaws.com/doc/2006-03-01'
        days = int(root.find('{%s}Days' % ns).text)
        return days

    def start_restoring(self, account, container, object, metadata=None):
        hidden_path = '/%s/%s/%s' % (account, container, object)
        part, nodes = self.container_ring.get_nodes(account, container)
        for node in nodes:
            ip = node['ip']
            port = node['port']
            dev = node['device']
            action_headers = dict()
            action_headers['user-agent'] = 'restore-daemon'
            action_headers['X-Timestamp'] = normalize_timestamp(time.time())
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


class LifecycleManageController(WSGIContext):
    def __init__(self, app, logger, account, container_name, **kwargs):
        WSGIContext.__init__(self, app)
        self.s3_accounts = '.s3_accounts'
        self.container_ring = Ring('/etc/swift', ring_name='container')
        self.account = account
        self.container = container_name
        self.logger = logger

    def GET(self, env, start_response):
        container_lc = ContainerLifecycle(self.account, self.container,
                                          env=env, app=self.app)

        lifecycle = container_lc.get_lifecycle()

        if container_lc.status != HTTP_NO_CONTENT:
            return Response(status=container_lc.status)

        if not lifecycle:
            resp = Response(content_type='text/xml')
            resp.status = HTTP_NOT_FOUND
            resp.body = '<?xml version="1.0" encoding="UTF-8"?>' \
                        '<Error><Code>NoSuchLifecycleConfiguration</Code>' \
                        '<Message>The lifecycle configuration' \
                        ' does not exist</Message>' \
                        '<BucketName>%s</BucketName></Error>' % self.container
            resp.headers[LIFECYCLE_RESPONSE_HEADER] = True
            return resp

        req = Request(copy(env))
        if 'lifecycle' in req.params:
            lifecycle = lifecycle_to_xml(lifecycle)

        elif 'lifecycle_rule' in req.params:
            try:
                lc_map = map(itemgetter('ID'), lifecycle)
                index = lc_map.index(req.params['lifecycle_rule'])
                rule = lifecycle[index]
                lifecycle = list()
                lifecycle.append(rule)
                lifecycle = lifecycle_to_xml(lifecycle)
            except Exception as e:
                return Response(status=400, body=e.message,
                                headers={LIFECYCLE_RESPONSE_HEADER: True})

        ret = Response(request=req, body=lifecycle,
                       headers={LIFECYCLE_RESPONSE_HEADER: True})
        return ret

    def DELETE(self, env, start_response):
        req = Request(copy(env))
        container_lc = ContainerLifecycle(self.account, self.container,
                                          env=env, app=self.app)

        if container_lc.status != HTTP_NO_CONTENT:
            if 'force_delete' not in req.params:
                return Response(status=container_lc.status)

        if container_lc.status != HTTP_NOT_FOUND \
            and 'force_delete' in req.params:
            return Response(status=container_lc.status)

        if 'lifecycle' in req.params:
            container_lc.delete_lifecycle()
            self.update_hidden_s3_account(self.account, self.container,
                                          'DELETE')
        elif 'lifecycle_rule' in req.params:
            lifecycle = container_lc.get_lifecycle()

            if not lifecycle:
                return Response(status=HTTP_NO_CONTENT)

            rule_id = req.params['lifecycle_rule']
            filtered_lc = filter(lambda x: x.get('ID') != rule_id, lifecycle)

            if not filtered_lc:
                container_lc.delete_lifecycle()
                self.update_hidden_s3_account(self.account, self.container,
                                              'DELETE')
            else:
                container_lc.set_lifecycle(filtered_lc)

        self.logger.increment('%s.%s.lifecycle.delete' % (self.account,
                                                          self.container))

        return Response(status=HTTP_NO_CONTENT)

    def PUT(self, env, start_response):
        try:
            req = Request(copy(env))

            if 'Content-MD5' not in req.headers:
                exceptMsg = dict()
                exceptMsg['status'] = 400
                exceptMsg['code'] = 'InvalidRequest'
                exceptMsg['msg'] = 'Missing required header for this ' \
                                   'request: Content-MD5'
                raise LifecycleConfigException(exceptMsg)

            lifecycle_xml = req.body
            lifecycle = xml_to_list(lifecycle_xml)

            if len(lifecycle) > 1000:
                raise Exception()

            xml_base64 = self.compute_xml_hash(lifecycle_xml)
            if xml_base64 != req.headers['Content-MD5']:
                exceptMsg = dict()
                exceptMsg['status'] = 400
                exceptMsg['code'] = 'InvalidRequest'
                exceptMsg['msg'] = 'Content-MD5 does not correct'
                raise LifecycleConfigException(exceptMsg)

            container_lc = ContainerLifecycle(self.account, self.container,
                                              env=env, app=self.app)

            prevLifecycle = container_lc.get_lifecycle()

            if container_lc.status != HTTP_NO_CONTENT:
                return Response(status=container_lc.status)

            if not prevLifecycle:
                prevLifecycle = list()

            if 'lifecycle_rule' in req.params:
                if len(lifecycle) > 1:
                    exceptMsg = dict()
                    exceptMsg['status'] = 400
                    exceptMsg['code'] = 'InvalidRequest'
                    exceptMsg['msg'] = 'more than one rule was uploaded'
                    raise LifecycleConfigException(exceptMsg)
                updateLifecycleMetadata(prevLifecycle, lifecycle)
                prevLifecycle.append(lifecycle[0])
                lifecycle = prevLifecycle

            if 'lifecycle' in req.params:
                updateLifecycleMetadata(prevLifecycle, lifecycle)

            check_lifecycle_validation(lifecycle)

            # 새로운 lifecycle로 변경
            set_result = container_lc.set_lifecycle(lifecycle)
            if set_result.status is not HTTP_CREATED:
                return set_result

            self.update_hidden_s3_account(self.account, self.container)

            self.logger.increment('%s.%s.lifecycle.put' %
                                  (self.account, self.container))
        except LifecycleConfigException as e:
            return get_err_response(e.message)
        except Exception as e:
            msg = dict()
            msg['status'] = 400
            msg['code'] = 'MalformedXML'
            msg['msg'] = 'The XML you provided was not well-formed or did ' \
                         'not validate against our published schema'
            return get_err_response(msg)
        return Response(status=200, app_iter='True',
                        headers={LIFECYCLE_RESPONSE_HEADER: True})

    def compute_xml_hash(self, xml):
        xml_md5 = md5()
        xml_md5.update(xml)
        xml_base64 = encodebytes(xml_md5.digest()).encode('utf-8')
        if xml_base64[-1] == '\n':
            xml_base64 = xml_base64[0:-1]
        return xml_base64

    def update_hidden_s3_account(self, account, container, method='PUT'):
        path = '/%s/%s/%s' % (self.s3_accounts, account, container)
        parts, nodes = self.container_ring.get_nodes(self.s3_accounts,
                                                     account)
        for node in nodes:
            ip = node['ip']
            port = node['port']
            dev = node['device']
            action_headers = dict()
            action_headers['user-agent'] = 'lifecycle'
            action_headers['X-Timestamp'] = normalize_timestamp(time.time())
            action_headers['referer'] = 'Lifecycle Middleware'
            action_headers['x-size'] = '0'
            action_headers['x-content-type'] = "text/plain"
            action_headers['x-etag'] = 'd41d8cd98f00b204e9800998ecf8427e'

            conn = http_connect(ip, port, dev, parts, method, path,
                                action_headers)
            response = conn.getresponse()
            response.read()


class LifecycleMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='lifecycle')
        self.logger.set_statsd_prefix('lifecycle-middleware')

    def get_controller(self, env, path):
        req = Request(env)
        version, account, container, obj = split_path(path, 0, 4, True)
        d = {'container_name': container,
             'object_name': unquote(obj) if obj is not None else obj,
             'account': account}

        if container and not obj:
            if 'lifecycle' in req.params or 'lifecycle_rule' in req.params:
                return LifecycleManageController, d

        if container and obj:
            return ObjectController, d

        return None, d

    def __call__(self, env, start_response):
        req = Request(env)

        if 'AWSAccessKeyId' in req.params:
            try:
                req.headers['Date'] = req.params['Expires']
                req.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % req.params
            except KeyError:
                return get_err_response({'status': 400,
                                         'code': 'InvalidArgument',
                                         'msg': 'InvalidArgument'})

        if 'Authorization' not in req.headers:
            return self.app(env, start_response)

        try:
            keyword, info = req.headers['Authorization'].split(' ')
        except:
            return get_err_response({'status': 403,
                                     'code': 'AccessDenied',
                                     'msg': 'AccessDenied'})

        if keyword != 'AWS':
            return get_err_response({'status': 403,
                                     'code': 'AccessDenied',
                                     'msg': 'AccessDenied'})
        try:
            account, signature = info.rsplit(':', 1)
        except:
            return get_err_response({'status': 400,
                                     'code': 'InvalidArgument',
                                     'msg': 'InvalidArgument'})

        self.logger.debug('Calling Lifecycle Middleware')

        controller, path_parts = self.get_controller(env, req.path)

        if controller is None:
            return self.app(env, start_response)
        controller = controller(self.app, self.logger, **path_parts)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(env, start_response)
        else:
            return get_err_response({'status': 400, 'code': 'InvalidURI',
                                     'msg': 'InvalidURI'})(env, start_response)

        return res(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return LifecycleMiddleware(app, conf)

    return lifecycle_filter
