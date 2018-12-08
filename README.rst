**NOTE:** THIS PROJECT HAS BEEN MOVED TO GITLAB: `https://gitlab.com/fhightower/ioc-finder/ <https://gitlab.com/fhightower/ioc-finder/>`_.


**IOC Finder**

.. image:: https://img.shields.io/pypi/v/ioc_finder.svg
        :target: https://pypi.python.org/pypi/ioc_finder

.. image:: https://img.shields.io/travis/fhightower/ioc-finder.svg
        :target: https://travis-ci.org/fhightower/ioc-finder

.. image:: https://codecov.io/gh/fhightower/ioc-finder/branch/master/graph/badge.svg
        :target: https://codecov.io/gh/fhightower/ioc-finder
        
.. image:: https://api.codacy.com/project/badge/Grade/6927955d30df40f395aa8adbd7b8bfe4
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/fhightower/ioc-finder

Find `indicators of compromise <https://searchsecurity.techtarget.com/definition/Indicators-of-Compromise-IOC>`_ in text.

Capabilities
============

Currently, this package can the following items in a given text:

- IP address (IPv4 and IPv6)
- Email addresses (both standard format (e.g. ``test@example.com``) and an email with an IP address as the domain (e.g. ``test@[192.168.0.1]``))
- Hosts (including unicode domain names (e.g. ``ȩxample.com``))
- URLs
- File Hashes (sha256, sha1, and md5)

Also provides some helpful features like:

- Ability to remove an indicator type after it is parsed - For example, this is helpful if you do not want to parse the host name from a URL. You can setup IOC Finder to remove all URLs from the text after it parses them.
- Ability to set order in which IOCs are parsed

Installation
============

To install this package:

.. code-block:: shell

    pip install ioc-finder

Usage
=====

To use this package:

.. code-block:: python

    from ioc_finder import find_iocs
    text = "This is just an example.com"
    iocs = find_iocs(text)
    print('Domains: {}'.format(iocs['domain']))

See `test_ioc_finder.py <https://github.com/fhightower/ioc-finder/blob/master/tests/test_ioc_finder.py>`_ for more examples.

Credits
=======

Many of the elements of this package also exist in `https://github.com/mosesschwartz/extract_iocs <https://github.com/mosesschwartz/extract_iocs>`_ which I've contributed to in the past.

This package was created with Cookiecutter_ and the `fhightower-templates/python-project-template`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`fhightower-templates/python-project-template`: https://github.com/fhightower-templates/python-project-template


.. image:: https://api.codacy.com/project/badge/Grade/4efdfbfa5a90457db37f9b807e32c167
   :alt: Codacy Badge
   :target: https://app.codacy.com/app/fhightower/ioc-finder?utm_source=github.com&utm_medium=referral&utm_content=fhightower/ioc-finder&utm_campaign=Badge_Grade_Settings