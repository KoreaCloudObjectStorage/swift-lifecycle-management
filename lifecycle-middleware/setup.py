from setuptools import setup

import lifecycle

setup(
    name='lifecycle',
    version=lifecycle.version,
    packages=['lifecycle'],
    url='http://a2company.co.kr',
    license='',
    author='nexusz99',
    author_email='nexusz99@a2company.co.kr',
    description='Swift Lifecycle Manamgment Middleware',
    requires=['swift(>=1.4)'],
    entry_points={'paste.filter_factory':
                        ['lifecycle=lifecycle.middleware:filter_factory']}
)
