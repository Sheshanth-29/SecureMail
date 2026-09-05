import os
import smtplib

sender = "Private Person <from@example.com>"
receiver = "A Test User <to@example.com>"
message = f"""\
Subject: Hi Mailtrap
To: {receiver}
From: {sender}
This is a test e-mail message."""

SMTP_USER = os.environ.get("MAILTRAP_USER")
SMTP_PASS = os.environ.get("MAILTRAP_PASS")

with smtplib.SMTP("sandbox.smtp.mailtrap.io", 2525) as server:
    server.starttls()
    server.login(SMTP_USER, SMTP_PASS)
    server.sendmail(sender, receiver, message)