import config

import opts

def send_email(subject, plaintext, people, sender=config.SENDER):
  # Import smtplib for the actual sending function
  import smtplib

  # Import the email modules we'll need
  from email.mime.text import MIMEText

  # Create a text/plain message
  msg = MIMEText(plaintext)

  # me == the sender's email address
  # you == the recipient's email address
  msg['Subject'] = subject
  msg['From'] = sender
  msg['To'] = (",").join(people)

  # Send the message via our own SMTP server, but don't include the
  # envelope header.
  s = smtplib.SMTP(config.SMTP_SERVER, config.PORT)
  if config.TLS:
    s.starttls()
  s.login(config.SMTP_USER, config.SMTP_PASS)
  s.sendmail(sender, people, msg.as_string())
  s.quit()


def email_peoples(msg, body, to_notify):
  if isinstance(to_notify, str):
    to_notify = [to_notify]

  if opts.SEND_EMAIL:
    print "SENDING EMAIL: %s" % msg
    send_email(msg, body, to_notify)


