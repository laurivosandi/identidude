LDAP to RESTful API bridge
==========================

This is a simple Falcon based API for easily manipulating data in LDAP server.

Features

* Add user by Estonian national identification number via ldap.sk.ee
* Delete users
* Reset password

Requirements:

* A LDAP server
* A SMTP server
* A web server

Dependencies:

    apt-get install python-pip python-cjson
    pip install falcon

