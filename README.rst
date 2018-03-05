*******************************
IOC Finder
*******************************

.. image:: https://img.shields.io/pypi/v/ioc_finder.svg
        :target: https://pypi.python.org/pypi/ioc_finder

.. image:: https://img.shields.io/travis/fhightower/ioc-finder.svg
        :target: https://travis-ci.org/fhightower/ioc-finder

.. image:: https://codecov.io/gh/fhightower/ioc-finder/branch/master/graph/badge.svg
        :target: https://codecov.io/gh/fhightower/ioc-finder
        
.. image:: https://api.codacy.com/project/badge/Grade/6927955d30df40f395aa8adbd7b8bfe4
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/fhightower/ioc-finder

Simple python package for finding indicators of compromise in text.

Installation
============

To install this package:

.. code-block:: shell

    pip install ioc_finder

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
