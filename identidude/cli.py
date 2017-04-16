#!/usr/bin/python
# encoding: utf-8

"""
Web interface for Microsoft Active Directory and Samba 4.x
"""

import click
import os
import sys

assert sys.version_info[0] >= 3, "Run with Python3!"

IDENTIDUDE_SERVICE = """[Unit]
Description=Identidude server
After=network.target

[Service]
PIDFile=/run/identidude.pid
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
ExecStart=%s serve

[Install]
WantedBy=multi-user.target
"""


@click.command("setup", help="Join domain, set up server")
@click.option("-h", "--hostname", default="id")
@click.option("-d", "--domain", required=True)
@click.option("-w", "--workgroup", required=True)
@click.option("-u", "--user", default="administrator", help="Administrative account for joining domain")
def identidude_setup(hostname, domain, workgroup, user):
    common = "samba python3-jinja2 python3-gssapi"
    if os.path.exists("/usr/bin/apt-get"):
        os.system("apt-get install -y -qq krb5-user " + common)
    elif os.path.exists("/usr/bin/yum"):
        os.system("yum install -y krb5-workstation " + common)
    else:
        click.echo("Unknown package management system, make sure you have Samba and Kerberos 5 utils installed")
    netbios_name = hostname.upper()
    with open("/etc/hosts", "w") as fh:
        fh.write("127.0.0.1 localhost\n")
        fh.write("127.0.1.1 %s.%s %s\n" % (hostname, domain, hostname))
        click.echo("Reset /etc/hosts")
    with open("/etc/samba/smb.conf", "w") as fh:
        fh.write("[global]\n")
        fh.write("workgroup = %s\n" % workgroup.upper())
        fh.write("realm = %s\n" % domain.upper())
        fh.write("netbios name =%s\n" % netbios_name)
        fh.write("security = ads\n")
        fh.write("kerberos method = system keytab\n")
        click.echo("Reset /etc/samba/smb.conf")
    with open("/etc/krb5.conf", "w") as fh:
        fh.write("[libdefaults]\n")
        fh.write("default_realm = %s\n" % domain.upper())
        fh.write("dns_lookup_realm = true\n")
        click.echo("Reset /etc/krb5.conf")

    if not os.path.exists("/tmp/krb5cc_%d" % os.getuid()):
        os.system("kinit " + user)
    if not os.path.exists("/etc/krb5.keytab"):
        click.echo("Joining domain %s" % domain)
        os.system("net ads join -k")
    if not os.path.exists("/etc/identidude/server.keytab"):
        click.echo("Adding HTTP service principal in /etc/identidude/server.keytab")
        if not os.path.exists("/etc/identidude"):
            os.makedirs("/etc/identidude")
        os.environ["KRB5_KTNAME"] = "FILE:/etc/identidude/server.keytab"
        os.system("net ads keytab add HTTP -k")
    else:
        click.echo("Remove /etc/identidude/server.keytab to regenerate")
    if not os.path.exists("/etc/cron.hourly/identidude"):
        with open("/etc/cron.hourly/identidude", "w") as fh:
            fh.write("#!/bin/bash\n")
            fh.write("kinit -k " + netbios_name + "\\$\n")
        click.echo("Created /etc/cron.hourly/identidude")
        os.chmod("/etc/cron.hourly/identidude", 0o755)
    else:
        click.echo("Remove /etc/cron.hourly/identidude to regenerate")

    click.echo("Disabling smbd nmbd services")
    os.system("systemctl stop nmbd smbd")
    os.system("systemctl mask nmbd smbd")

    click.echo("Creating systemd service /etc/systemd/system/identidude.service")
    with open("/etc/systemd/system/identidude.service", "w") as fh:
        fh.write(IDENTIDUDE_SERVICE % sys.argv[0])


@click.command("purge", help="Disable server and unjoin domain")
@click.option("-u", "--user", default="administrator", help="Administrative account for leaving domain")
def identidude_purge(user):
    if not os.path.exists("/tmp/krb5cc_%d" % os.getuid()):
        os.system("kinit " + user)
    os.system("net ads leave -k")
    os.unlink("/etc/samba/smb.conf")
    os.unlink("/etc/krb5.keytab")
    os.unlink("/etc/identidude/server.keytab")


@click.command("serve", help="Run server")
@click.option("-p", "--port", default=80, help="Listen port")
@click.option("-l", "--listen", default="0.0.0.0", help="Listen address")
def identidude_serve(port, listen):
    from wsgiref import simple_server
    from identidude.api import app
    click.echo("Listening on %s:%s" % (listen, port))
    httpd = simple_server.make_server(listen, port, app)
    httpd.serve_forever()


@click.group()
def entry_point(): pass

entry_point.add_command(identidude_setup)
entry_point.add_command(identidude_purge)
entry_point.add_command(identidude_serve)

if __name__ == "__main__":
    entry_point()
