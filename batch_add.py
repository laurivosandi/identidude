#!/usr/bin/python3

"""
Batch user addition utility

Usage:

python3 batch_add.py -e http://ldap.example.org/api/ -d department.organization.example.org -u your-username -p your-password path-to.csv

Note that CSV file headers will be probed and the CSV file content will be updated accordingly.
We're mainly using Python3 because Python2 doesn't handle Unicode well.

Currently this utility probes for following tab delimited headers. Username and password fields will be overwritten:

* Isikukood
* Eesnimi
* Perekonnanimi
* Kasutajanimi
* Parool
* Lähtestamise e-post

"""

import os
import re
from getpass import getpass
from time import sleep
from optparse import OptionParser
import unicodedata
import urllib.request
import urllib.parse
import http.client
import json

class NotFoundError(Exception):
    pass


RE_ID = "[3-6]\d\d\d\d\d\d\d\d\d\d"

def normalize_username(first, last, serialNumber):
    username = first[0] + last + serialNumber[-4:]
    username = username.replace("-", "")
    username = username.replace(" ", "")
    username = unicodedata.normalize("NFKD", (username).lower()).encode("ascii", "ignore").decode("ascii")
    return username


class API(object):
    def __init__(self, url):
        o = urllib.parse.urlparse(url)
        self.hostname = o.netloc
        self.conn = http.client.HTTPConnection(self.hostname)
        self.base = o.path
        self.cookie = None
        
    def query(self, method, endpoint, **body):
        path = self.base + endpoint #+ "?" + "&".join(["%s=%s" % (k,v) for k,v in params.items()])
        headers = {"content-type": "application/json", "accept-encoding": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        fh = self.conn.request(method, path, json.dumps(body), headers)
        response = self.conn.getresponse()
        set_cookie = response.getheader("set-cookie")
        buf = response.read()
        if set_cookie:
            self.cookie, _ = set_cookie.split(";", 1)
        if response.status >= 200 and response.status < 300:
            if buf:
                return json.loads(buf.decode("utf-8"), encoding="utf-8")
            else:
                return {}
        if response.status == 404:
            raise NotFoundError()
        raise Exception("Request returned %d %s: %s" % (response.status, response.reason, response.read()))

    def login(self, **kwargs):
        me = self.query("POST", "/session/", **kwargs)
        return me
        
    def lookup(self, *ids):
        return self.query("GET", "/lookup/", ids=ids)
        
    def user_list(self, domain=None):
        return self.query("GET", ("/domain/%s/user/" % domain) if domain else "/user/", cookie=self.cookie)
        
    def user_add(self, domain, **params):
        return self.query("POST", "/domain/%s/user/" % domain, **params)
        
    def userdel(self, domain, username):
        return self.query("DELETE", "/domain/%s/user/%s/" % (domain, username))
        
    def reset_password(self, domain, username):
        return self.query("PUT", "/domain/%s/user/%s/password/" % (domain, username))

from openpyxl import load_workbook
        
def main(options, *filenames):
    import csv
    rows = []
    api = API(options.endpoint)
    api.login(username=options.username, password=options.password)

    for filename in filenames:
        with open(filename) as fh:
            probe_headers = True
            
            column_serial_number = None
            column_first_name = None
            column_last_name = None
            column_username = None
            column_initial_password = None
            column_recovery_email = None
            
            for row in csv.reader(fh, delimiter="\t"):
                rows.append(row)
                
        serial_numbers = set()
            
        for row in rows:
            if not row:
                continue

            if probe_headers:
                for offset, cell in enumerate(row):
                    if cell in ("Isikukood",):
                        column_serial_number = offset
                    elif cell in ("Eesnimi",):
                        column_first_name = offset
                    elif cell in ("Perekonnanimi", "Perenimi"):
                        column_last_name = offset
                    elif cell in ("Parool",):
                        column_initial_password = offset
                    elif cell in ("Kasutajanimi"):
                        column_username = offset
                    elif cell in ("Lähtestamise e-post"):
                        column_recovery_email = offset
                probe_headers = False
                continue

            assert column_serial_number
            assert column_first_name
            assert column_last_name
            assert column_initial_password
            assert column_username
            assert column_recovery_email
            
            serial_number = row[column_serial_number]
            
            if not serial_number:
                continue
                
            serial_numbers.add(serial_number)
                    
        results = api.lookup(*serial_numbers)
        
        for row in rows[1:]:
            if not row:
                continue
                
            serial_number = row[column_serial_number]
            initial_password = row[column_initial_password]

            if not re.match(RE_ID, serial_number):
                continue

            recovery_email = row[column_recovery_email]
                
            if serial_number in results:
                first_name = results[serial_number]["gn"]
                last_name = results[serial_number]["sn"]
                if not row[column_recovery_email]:
                    recovery_email = results[serial_number]["email"]
            else:
                first_name = row[column_first_name]
                last_name = row[column_last_name]
                assert len(first_name) >= 2
                assert len(last_name) >= 3
                
            username = normalize_username(first_name, last_name, serial_number)
        
            first_name = re.sub("\s*\-\s*", "-", first_name)
            first_name = re.sub("\s+", " ", first_name)

            last_name = re.sub("\s*\-\s*", "-", last_name)
            last_name = re.sub("\s+", " ", last_name)
            
            first_name = first_name.title()
            last_name = last_name.title()
            
            row[column_username] = username
            row[column_recovery_email] = recovery_email
            row[column_first_name] = first_name
            row[column_last_name] = last_name

            fullname = "%s %s" % (first_name, last_name)
            
            if row[column_initial_password]:
                print("Initial password set for %s, skipping user creation" % username)
                continue

            try:
                print("Deleting user:", username)
                api.userdel("meripohi.edu.ee", username)
            except NotFoundError:
                pass

            kwargs = dict(
                batch = 1,
                id = serial_number,
                email = recovery_email,
                username = username,
                cn = first_name + " " + last_name,
                group = options.group)
            print("Creating user:", kwargs)
            profile = api.user_add(options.domain, **kwargs)
            
            row[column_initial_password] = profile["initial_password"]
            
            # Atomic! save
            with open(filename + ".part", "w") as fh:
                writer = csv.writer(fh, delimiter="\t")
                for row in rows:
                    writer.writerow(row)
            os.rename(filename + ".part", filename)
                
if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-e", "--endpoint", dest="endpoint", default="http://ldap.povi.ee/api/")
    parser.add_option("-d", "--domain", dest="domain", help="Domain for user accounts")
    parser.add_option("-g", "--group", dest="group", default="students", help="Primary POSIX group")
    parser.add_option("-p", "--password", dest="password", help="API password")
    parser.add_option("-u", "--username", dest="username", help="API username")

    (options, filenames) = parser.parse_args()

    if not options.domain:
        raise ValueError("No domain specified")
    if not options.username:
        raise ValueError("No username specified")
    if not options.password:
        options.password = getpass("Enter password for http://%s@%s: " % (options.username, options.domain))
        
    main(options, *filenames)

