Swift S3 Lifecycle
------

Install Middleware
-------

1) Install Swift-Lifecycle-Management with ``sudo python setup install`` or via debian packaging (dpkg)

2) Alter your proxy-server.conf pipeline to have swiftlifecyclemanagement
  
    [pipeline:main]
    pipeline = catch_errors cache swift3 s3token authtoken keystoneauth swiftlifecyclemanagement proxy-server
  
  [Note] swiftlifecyclemanagement middleware always located after auth middleware

3) Add to your proxy-server.conf the section for the swiftlifecyclemanagement WSGI filter

    [filter:swiftlifecyclemanagement]
    use = egg:swiftlifecyclemanagement#swiftlifecyclemanagement
    log_level = INFO
  
4) After install middleware and make sure your that proxy-server.con has swiftlifecyclemanagement middleware, restart proxy-server to load new middleware
  
Install Daemon
-------
Working...
