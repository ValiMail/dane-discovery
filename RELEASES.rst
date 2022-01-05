Release Workflow
================

Release from the ``main`` branch.

When committing to this repository, please follow the
`formatting guidelines for gitchangelog <https://github.com/vaab/gitchangelog>`_ .
This will help to organize the auto-generated change log in a meaningful way.

The process for releasing new versions of this software package are as follows:

* Update the ``__init__.py`` file to reflect the new version identifier.
* Update the changelog, using the ``gitchangelog`` utility: ``gitchangelog > CHANGELOG.rst``
* Commit the changes to ``__init__.py`` and ``CHANGELOG.rst``
* Tag the new version, prepending ``v`` to the semantic version. For instance, if ``__version__ = "0.20"``, then the git tag should be ``v0.20``
* Push to the ``main`` branch with ``git push origin main --tags``.
* Pushing a tagged version to git will trigger a release through PyPI and a documentation build via readthedocs.org.