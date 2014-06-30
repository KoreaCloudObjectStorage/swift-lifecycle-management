from distutils.core import setup

setup(
    name='truncate',
    version='0.0.1',
    packages=['common', 'daemon'],
    url='http://a2company.co.kr',
    license='',
    author='nexusz99',
    author_email='nexusz99@a2company.co.kr',
    description='Swift Object Truncate Middleware',
    requires=['swift(>=1.4)'],
    entry_points={'paste.filter_factory':
                  ['truncate=truncate.middleware:filter_factory']}
)
