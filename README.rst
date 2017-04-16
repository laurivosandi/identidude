Active Directory/Samba web interface
====================================

This is a simple Falcon based web interface for easily manipulating data in domain controller.

Features

* Add user by Estonian national identification number via ldap.sk.ee
* Delete users
* Reset password

Setup
-----

Use clean Ubuntu 16.04 virtual machine.

Bootstrap installation by running:

  identidude -d example.lan -w WORKGROUP -u Administrator

During this several procedures are performed:

* Necessary software packages are installed
* Domain administrator password will be prompted
* Samba suite is configured to behave as domain member
* Computer is joined to domain
* HTTP service principal is created
* Cronjob for updating LDAP service ticket is created
* systemd service files are created

Finally start the service:

  systemctl start identidude

For debugging:

  journalctl -f

Point your web browser to the id.example.lan, if necessary configure
credential delegation on your web browser.
To prevent domain administrator account abuse configure
user management delegation for your account.

