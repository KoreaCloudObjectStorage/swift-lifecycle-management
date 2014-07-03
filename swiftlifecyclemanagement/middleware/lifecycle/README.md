lifecycle
-------

lifecycle 는 openstack swift의 middleware이다.
container 별로 lifecycle 정책을 설정하여 object의 lifecycle을 관리해주는 기능을 담당한다.
Swift3와 연동되어, Amazon S3 API를 이용하여 사용이 가능하다.

Install
-------

0)  선행작업으로 [swift3](https://github.com/fujita/swift3)이 설치되어 있어야한다.

1)  lifecycle을 설치하기 위해서는 ``sudo python setup.py install`` 또는
    ``sudo python setup.py develop``를 이용하여 설치할 수 있다.

2)  proxy-server.conf의 pipeline에 lifecycle을 추가한다.

Tempauth 를 사용할 경우:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache swift3 tempauth proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache swift3 tempauth lifecycle proxy-server


3)  proxy-server.conf 의 section에 lifecycle WSGI filter 를 추가한다.

    [filter:lifecycle]
    use = egg:lifecycle#lifecycle

주의 사항
-------

0)  keystone 인증을 사용할 경우, lifecycle middleware를 keystone 뒤에 설정하여야 한다. (keystone을 거쳐야 정상적인 account 값이 설정됨)