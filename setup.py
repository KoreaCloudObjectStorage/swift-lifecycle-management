from setuptools import setup

from middleware import lifecycle

setup(
    name='lifecycle',
    version=lifecycle.version,
    packages=['middleware.lifecycle', 'common'],
    url='http://a2company.co.kr',
    license='',
    author='nexusz99',
    author_email='nexusz99@a2company.co.kr',
    description='Swift Lifecycle Manamgment Middleware',
    requires=['swift(>=1.4)'],
    entry_points={'paste.filter_factory':
                        ['lifecycle=middleware.lifecycle'
                         '.middleware:filter_factory']}
)