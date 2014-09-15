import jinja2
import os
import smtplib
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
        for key, value in context.items():
            print key, "=>", type(value), value
        if isinstance(recipients, list) or isinstance(recipients, tuple):
            for recipient in recipients:
                assert isinstance(recipient, basestring), "Invalid recipient: %s (%s)" % (recipient, type(recipient))
            recipients = ", ".join(recipients)

        assert isinstance(recipients, str), "Invalid recipient: %s" % recipients
        assert isinstance(sender, str)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipients
        
        text = self.env.get_template(template + ".txt").render(context).encode("utf-8")
        html = self.env.get_template(template + ".html").render(context).encode("utf-8")
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        
        msg.attach(part1)
        msg.attach(part2)
        
        self.server.sendmail(sender, recipients, msg.as_string())
