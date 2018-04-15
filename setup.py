#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('LICENSE') as license_file:
    license = license_file.read()

requirements = [
    # TODO: put package requirements here
]

test_requirements = [
    # TODO: put package test requirements here
]

setup(
    name='ioc_finder',
    version='0.1.5',
    description="Simple python package for finding indicators of compromise in text.",
    long_description=readme,
    author="Floyd Hightower",
    author_email='',
    url='https://github.com/fhightower/ioc-finder',
    packages=find_packages(exclude=('tests', 'docs')),
    include_package_data=True,
    package_data={'ioc_finder': ['data/*',]},
    install_requires=requirements,
    license=license,
    zip_safe=True,
    keywords='ioc_finder',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
