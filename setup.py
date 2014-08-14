from setuptools import setup, find_packages

import swiftlifecyclemanagement

filter_factory = [
    'swiftlifecyclemanagement=swiftlifecyclemanagement.middleware.lifecycle.middleware:filter_factory',
    'swiftobjecttransiton=swiftlifecyclemanagement.middleware.transition.middleware:filter_factory',
    'swiftobjectrestore=swiftlifecyclemanagement.middleware.restorer.middleware:filter_factory',
    'swiftobjecttruncate=swiftlifecyclemanagement.middleware.truncate.middleware:filter_factory'
]

setup(
    name='swiftlifecyclemanagement',
    version=swiftlifecyclemanagement.version,
    packages=find_packages(),
    url='http://a2company.co.kr',
    license='',
    author='nexusz99',
    author_email='nexusz99@a2company.co.kr',
    description='Swift Lifecycle Manamgment Middleware',
    install_requires=['swift >= 1.13.1', 'boto >= 2.32.1'],
    entry_points={'paste.filter_factory': filter_factory}
)
