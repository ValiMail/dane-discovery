Changelog
=========


v0.19
-----

New
~~~
- Configurable DNS timeout. [Ash Wilson]

  Close #77
- Add Identity.cert_matches_private_key() [Ash Wilson]

  Close #78

Other
~~~~~
- Build(deps): update pytest-cov requirement from ~=2.12 to ~=3.0.
  [dependabot[bot]]

  Updates the requirements on [pytest-cov](https://github.com/pytest-dev/pytest-cov) to permit the latest version.
  - [Release notes](https://github.com/pytest-dev/pytest-cov/releases)
  - [Changelog](https://github.com/pytest-dev/pytest-cov/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest-cov/compare/v2.12.0...v3.0.0)

  ---
  updated-dependencies:
  - dependency-name: pytest-cov
    dependency-type: direct:production
  ...


v0.18 (2021-09-30)
------------------
- Build(deps): update cryptography requirement from ~=3.0 to >=3,<36.
  [dependabot[bot]]

  Updates the requirements on [cryptography](https://github.com/pyca/cryptography) to permit the latest version.
  - [Release notes](https://github.com/pyca/cryptography/releases)
  - [Changelog](https://github.com/pyca/cryptography/blob/main/CHANGELOG.rst)
  - [Commits](https://github.com/pyca/cryptography/compare/3.0...35.0.0)

  ---
  updated-dependencies:
  - dependency-name: cryptography
    dependency-type: direct:production
  ...
- Build(deps): update sphinx requirement from ~=4.1 to ~=4.2.
  [dependabot[bot]]

  Updates the requirements on [sphinx](https://github.com/sphinx-doc/sphinx) to permit the latest version.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v4.1.0...v4.2.0)

  ---
  updated-dependencies:
  - dependency-name: sphinx
    dependency-type: direct:production
  ...


v0.17 (2021-07-20)
------------------

New
~~~
- Identity.get_pkix_cd_trust_chain returns a structured trust chain.
  [Ash Wilson]
- PKIX-CD authentication supports multi-tier PKI hierarchy. [Ash Wilson]

Changes
~~~~~~~
- Fix issues related to badly-generated markdown. [Ash Wilson]
- Refactor, breaking changes. Read the docs before pinning to this
  release. [Ash Wilson]
- Resolver override available or applied throughout. [Ash Wilson]

  Close #70

Other
~~~~~
- Build(deps): update requests requirement. [dependabot[bot]]

  Updates the requirements on [requests](https://github.com/psf/requests) to permit the latest version.
  - [Release notes](https://github.com/psf/requests/releases)
  - [Changelog](https://github.com/psf/requests/blob/master/HISTORY.md)
  - [Commits](https://github.com/psf/requests/compare/v2.24.0...v2.26.0)

  ---
  updated-dependencies:
  - dependency-name: requests
    dependency-type: direct:production
  ...
- Build(deps): update sphinx requirement from ~=4.0 to ~=4.1.
  [dependabot[bot]]

  Updates the requirements on [sphinx](https://github.com/sphinx-doc/sphinx) to permit the latest version.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v4.0.0...v4.1.0)

  ---
  updated-dependencies:
  - dependency-name: sphinx
    dependency-type: direct:production
  ...


v0.16 (2021-06-08)
------------------

New
~~~
- Establish compatibility with Python 3.6, 3.7, and 3.8. [Ash Wilson]


v0.15 (2021-06-05)
------------------

Fix
~~~
- Correct issue with CLI scripts being excluded from package. [Ash
  Wilson]


v0.14 (2021-06-04)
------------------

Changes
~~~~~~~
- Increment minor version, update CHANGELOG.rst. [Ash Wilson]
- Include /.well-known/ in CA URL. [Ash Wilson]

  Close #62


v0.13 (2021-06-04)
------------------

Changes
~~~~~~~
- Incerement minor version, update CHANGELOG.rst. [Ash Wilson]
- Retrieving invalid TLSA record from DNS throws TLSAError. [Ash Wilson]

  Close #59
- Update pattern for generating authority server URL. [Ash Wilson]

  Close #58


v0.12 (2021-05-28)
------------------

New
~~~
- Implement new method for Identity to retrieve first entity
  certificate. [Ash Wilson]

  Close #56

Other
~~~~~
- Build(deps): update requests-mock requirement from ~=1.9.2 to ~=1.9.3.
  [dependabot[bot]]

  Updates the requirements on [requests-mock](https://github.com/jamielennox/requests-mock) to permit the latest version.
  - [Release notes](https://github.com/jamielennox/requests-mock/releases)
  - [Commits](https://github.com/jamielennox/requests-mock/compare/1.9.2...1.9.3)


v0.11 (2021-05-18)
------------------
- Build(deps): update pytest-cov requirement from ~=2.11 to ~=2.12.
  [dependabot[bot]]

  Updates the requirements on [pytest-cov](https://github.com/pytest-dev/pytest-cov) to permit the latest version.
  - [Release notes](https://github.com/pytest-dev/pytest-cov/releases)
  - [Changelog](https://github.com/pytest-dev/pytest-cov/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest-cov/compare/v2.11.0...v2.12.0)


v0.10 (2021-05-11)
------------------

Changes
~~~~~~~
- Generate DER certificates, include as a control in testing when
  changing representations between PEM, TLSA, DER. [Ash Wilson]

Other
~~~~~
- Build(deps): update requests requirement from ~=2.24.0 to
  >=2.24,<2.26. [dependabot[bot]]

  Updates the requirements on [requests](https://github.com/psf/requests) to permit the latest version.
  - [Release notes](https://github.com/psf/requests/releases)
  - [Changelog](https://github.com/psf/requests/blob/master/HISTORY.md)
  - [Commits](https://github.com/psf/requests/compare/v2.24.0...v2.25.1)
- Build(deps): bump dnspython from 2.0.0 to 2.1.0. [dependabot[bot]]

  Bumps [dnspython](https://github.com/rthalley/dnspython) from 2.0.0 to 2.1.0.
  - [Release notes](https://github.com/rthalley/dnspython/releases)
  - [Changelog](https://github.com/rthalley/dnspython/blob/master/doc/whatsnew.rst)
  - [Commits](https://github.com/rthalley/dnspython/compare/v2.0.0...v2.1.0)
- Build(deps): update pytest-cov requirement from ~=2.10 to ~=2.11.
  [dependabot[bot]]

  Updates the requirements on [pytest-cov](https://github.com/pytest-dev/pytest-cov) to permit the latest version.
  - [Release notes](https://github.com/pytest-dev/pytest-cov/releases)
  - [Changelog](https://github.com/pytest-dev/pytest-cov/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest-cov/compare/v2.10.0...v2.11.1)
- Build(deps): update requests-mock requirement from ~=1.8.0 to ~=1.9.2.
  [dependabot[bot]]

  Updates the requirements on [requests-mock](https://github.com/jamielennox/requests-mock) to permit the latest version.
  - [Release notes](https://github.com/jamielennox/requests-mock/releases)
  - [Commits](https://github.com/jamielennox/requests-mock/compare/1.8.0...1.9.2)
- Build(deps): update sphinx requirement from ~=3.1 to ~=4.0.
  [dependabot[bot]]

  Updates the requirements on [sphinx](https://github.com/sphinx-doc/sphinx) to permit the latest version.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.1.0...v4.0.1)
- Build(deps): update pytest requirement from ~=6.0 to ~=6.2.
  [dependabot[bot]]

  Updates the requirements on [pytest](https://github.com/pytest-dev/pytest) to permit the latest version.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/main/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.0.0...6.2.4)
- Create dependabot.yml. [Peter Goldstein]


v0.9 (2021-03-02)
-----------------

Changes
~~~~~~~
- Add filtering to certificate retrieval tool. [Ash Wilson]

  Close #39
- Rename CLI sc8ripts to align with package name. [Ash Wilson]

  Close #38


v0.8 (2021-02-27)
-----------------

New
~~~
- Add dane_pkix_cd_get_ca_certificates. [Ash Wilson]

  Close #32
- Add dane_pkix_cd_get_certificates. [Ash Wilson]

  Close #31
- Add authenticate_pkix_cd script. [Ash Wilson]

  Close #29
- Add PKIX-CD validation for local certificates. [Ash Wilson]

  Close #28


v0.7 (2021-02-18)
-----------------

New
~~~
- Add certificate_object to output from Identity.process_tlsa() [Ash
  Wilson]

  Close #23
- Add support for EC certificates and keys. [Ash Wilson]

  Close #24


v0.6 (2020-11-10)
-----------------

New
~~~
- Add support for PKIX-CD. [Ash Wilson]

  Breaking changes! Test thoroughly before updating to this version!

  Close #20
- Add Identity.get_ca_certificate_for_identity() [Ash Wilson]

  Close #18
- Add Identity.verify_certificate_signature(). [Ash Wilson]


v0.5 (2020-10-15)
-----------------

Fix
~~~
- Clean up parsing of TLSA records when DNSSEC is in use. [Ash Wilson]


v0.4 (2020-10-15)
-----------------

Fix
~~~
- Fix parsing of full DNS response message. [Ash Wilson]


v0.3 (2020-10-15)
-----------------

New
~~~
- Identity __repr__() indicates request context and x509 extensions.
  [Ash Wilson]

Changes
~~~~~~~
- DANE.get_tlsa_records() returns request context. [Ash Wilson]


v0.2 (2020-08-13)
-----------------

New
~~~
- Support generating TLSA records for matching type 1, 2. [Ash Wilson]

  Closes #3


v0.1 (2020-08-04)
-----------------

New
~~~
- Add certificate_association_to_der() and der_to_pem() for formatting
  certs from TLSA RRs. [Ash Wilson]


