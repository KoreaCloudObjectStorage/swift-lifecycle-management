Truncate
-------

Truncate 는 openstack swift Object Server의 middleware이다.
POST 요청에 대해 헤더에 'X-Object-Meta-Truncate' 가 설정되어 있으면, 해당 파일을 0KB로 만들고 'X-Object-Meta-Glacier' 메타데이터를 True로 설정한다.

Install
-------

0)  Truncate을 설치하기 위해서는 ``sudo python setup.py install`` 또는
    ``sudo python setup.py develop``를 이용하여 설치할 수 있다.

1)  object-server.conf의 pipeline에 truncate을 추가한다.

Tempauth 를 사용할 경우:

    Was::

        [pipeline:main]
		pipeline = healthcheck recon object-server

    Change To::

        [pipeline:main]
        pipeline = healthcheck recon truncate object-server


2)  object-server.conf 의 section에 Truncate WSGI filter 를 추가한다.

    [filter:truncate]
    use = egg:truncate#truncate
