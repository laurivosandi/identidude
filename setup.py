#!/usr/bin/env python3
# coding: utf-8
import os
from setuptools import setup

setup(
    name = "identidude",
    version = "0.1.1",
    author = u"Lauri Võsandi",
    author_email = "lauri.vosandi@gmail.com",
    description = "identidude is a web based interface for Samba 4.x and Microsoft AD",
    license = "MIT",
    keywords = "falcon http jinja2 kerberos ldap",
    url = "http://github.com/laurivosandi/identidude",
    packages=[
        "identidude",
        "identidude.api"
    ],
    long_description=open("README.rst").read(),
    install_requires=[
        "click",
        "cryptography", # The one in APT repos doesn't have OpenSSL key serialization
        "falcon",
        "pyldap" # For Python3 support
    ],
    scripts=[
        "misc/identidude"
    ],
    include_package_data = True,
    package_data={
        "identidude": ["identidude/templates/*"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: Freely Distributable",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
    ],
)

