# -*- coding: utf-8 -*-
import sys
from setuptools import setup

REQUIRES = ['werkzeug>=0.10.4']
if sys.version_info < (3, 4):
    REQUIRES.append('enum34>=1.0.4')

def read(fname):
    with open(fname) as fp:
        content = fp.read()
    return content

setup(
    name='hmac_authentication',
    version='1.0.0',
    description='Signs and validates HTTP requests based on a shared-secret HMAC signature',
    long_description=read('README.md'),
    author='Mike Bland',
    author_email='mbland@acm.org',
    url='https://github.com/18F/hmac_authentication_py',
    packages=['hmac_authentication'],
    include_package_data=True,
    license=read('LICENSE.md'),
    zip_safe=False,
    keywords='hmac-authentication',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    install_requires=REQUIRES,
    test_suite='nose.collector',
    tests_require=['nose'],
)
