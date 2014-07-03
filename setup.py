from setuptools import setup, find_packages

import swiftlifecyclemanagement

setup(
    name='swiftlifecyclemanagement',
    version=swiftlifecyclemanagement.version,
    packages=find_packages(),
    url='http://a2company.co.kr',
    license='',
    author='nexusz99',
    author_email='nexusz99@a2company.co.kr',
    description='Swift Lifecycle Manamgment Middleware',
    requires=['swift(>=1.4)'],
    entry_points={'paste.filter_factory':
                        ['swiftlifecyclemanagement=swiftlifecyclemanagement.middleware.lifecycle.middleware:filter_factory']}
)
