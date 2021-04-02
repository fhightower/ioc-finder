from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

requirements = ['pyparsing', 'ioc_fanger', 'click']

setup(
    name='ioc_finder',
    version='5.0.2',
    description="Python package for finding and parsing indicators of compromise from text.",
    entry_points={'console_scripts': ['ioc-finder=ioc_finder.ioc_finder:cli_find_iocs']},
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Floyd Hightower",
    author_email='',
    url='https://github.com/fhightower/ioc-finder',
    packages=find_packages(exclude=('tests', 'docs')),
    include_package_data=True,
    install_requires=requirements,
    license='MIT',
    zip_safe=True,
    keywords='iocs,indicators of compromise,parsing,finding,searching,threat intelligence,malware,threat hunting,observables,domains,domain names,asns,cidr,cidr ranges,ips,ip addresses,urls,email addresses,md5,sha1,sha256,google ads,cve,file paths',
    test_suite='tests',
)
