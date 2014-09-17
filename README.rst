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

.. code:: bash

    apt-get install python-pip python-cjson
    pip install falcon

Screenshots:

.. figure:: http://lauri.vosandi.com/cache/f47f9aa9a89a6f3a711ec299124cdb46.png

    Home screen has links to the main editable resources, nothing excessive

.. figure:: http://lauri.vosandi.com/cache/99f082379b3fcbb04826039ef447fb16.png

    Domains are abstracted as list of organizations

.. figure:: http://lauri.vosandi.com/cache/425ef14896db38f0c3db24c66d053cd7.png

    Users can be added by Estonian national identification number
