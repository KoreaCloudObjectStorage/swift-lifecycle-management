from distutils.core import setup

setup(
    name='transition',
    version='0.0.1',
    packages=['common', 'daemon'],
    url='http://a2company.co.kr',
    license='',
    author='nexusz99',
    author_email='nexusz99@a2company.co.kr',
    description='Swift Object Transitioning Middleware',
    requires=['swift(>=1.4)'],
    entry_points={'paste.filter_factory':
                  ['transition=transition.middleware:filter_factory']}
)
