import jinja2
import os
import smtplib
from time import sleep
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class Mailer(object):
    def __init__(self, server, port=25, username=None, password=None, secure=False):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.secure = secure
        self.templates = jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates"))
        self.env = jinja2.Environment(loader=self.templates)
        self.reconnect()

    def reconnect(self):
        # Gmail employs some sort of IPS
        # https://accounts.google.com/DisplayUnlockCaptcha
        self.server = smtplib.SMTP("%s:%d" % (self.server, self.port))
        if self.secure:
            self.server.starttls()
        if self.username and self.password:
            self.server.login(self.username, self.password)
        
    def enqueue(self, sender, recipients, subject, template, **context):
        backoff = 1
        while True:
            try:
                self.send(sender, recipients, subject, template, **context)
                return
            except smtplib.SMTPServerDisconnected:
                print("Connection to %s unexpectedly closed, probably TCP timeout, backing off for %d second" % (self.server, backoff))
                self.reconnect()
                backoff = backoff * 2
                sleep(backoff)
        
    def send(self, sender, recipients, subject, template, **context):
        assert isinstance(sender, basestring)
        
        print "Sending e-mail to:", recipients

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients) if  isinstance(recipients, list) or isinstance(recipients, tuple) else recipients
        
        text = self.env.get_template(template + ".txt").render(context).encode("utf-8")
        html = self.env.get_template(template + ".html").render(context).encode("utf-8")
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        
        msg.attach(part1)
        msg.attach(part2)
        
        self.server.sendmail(sender, recipients, msg.as_string())
