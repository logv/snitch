SNORKEL_URL = None
SMTP_SERVER = "mail.you.com"
SMTP_USER = "email_user@email_domain.com"
SMTP_PASS = "email_password"
SENDER = "stuping@email_domain.com"
PORT = 25 # 25 = Regular, 465 = SSL, 587 = TLS
TLS = 0 # Require TLS 0 = No, 1 = Yes

# Import local settings, too
try:
  from local import *
except Exception as e:
  print("Couldnt import local settings")
  print(e)
