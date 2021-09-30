"""Setup script for dane-discovery."""
import os
import re
from setuptools import setup, find_packages


PROJECT_NAME = "dane_discovery"


def get_file_contents(file_name):
    """Return the contents of a file."""
    with open(os.path.join(os.path.dirname(__file__), file_name), 'r') as f:
        return f.read()


def get_version():
    """Return the package version."""
    init_file = get_file_contents(os.path.join(PROJECT_NAME, "__init__.py"))
    rx_compiled = re.compile(r"\s*__version__\s*=\s*\"(\S+)\"")
    ver = rx_compiled.search(init_file).group(1)
    return ver


def build_long_desc():
    """Return the long description of the package."""
    return "\n".join([get_file_contents(f) for f in ["README.rst"]])


setup(name=PROJECT_NAME,
      version=get_version(),
      author="Ash Wilson",
      author_email="ash.d.wilson@gmail.com",
      description="A library for using DANE for public key discovery.",
      license="BSD",
      keywords="dane tlsa dns certificate discovery",
      url="https://github.com/valimail/{}".format(PROJECT_NAME),
      long_description=build_long_desc(),
      long_description_content_type="text/x-rst",
      packages=["dane_discovery", "dane_discovery.scripts"],
      entry_points={
          "console_scripts": [
              "dane_discovery_get_certificates = dane_discovery.scripts.dane_discovery_get_certificates:main",
              "dane_discovery_authenticate_certificate = dane_discovery.scripts.dane_discovery_authenticate_certificate:main",
              "dane_discovery_get_ca_certificates = dane_discovery.scripts.dane_discovery_get_ca_certificates:main"
          ]
      },
      install_requires=["dnspython==2.1.0", 
                        "cryptography>=3,<36",
                        "requests>=2.24,<2.27",
                        "forcediphttpsadapter"],
      classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
        "License :: OSI Approved :: BSD License"
        ],)
