#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('LICENSE') as license_file:
    license = license_file.read()

requirements = [
    'pyparsing',
    'ioc_fanger'
]

setup(
    name='ioc_finder',
    version='1.2.2',
    description="Python package for finding and parsing indicators of compromise from text.",
    long_description=readme,
    author="Floyd Hightower",
    author_email='',
    url='https://github.com/fhightower/ioc-finder',
    packages=find_packages(exclude=('tests', 'docs')),
    include_package_data=True,
    install_requires=requirements,
    license=license,
    zip_safe=True,
    keywords='iocs indicators of compromise parsing finding searching threat intelligence',
    test_suite='tests'
)
