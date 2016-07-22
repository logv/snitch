
PRINT_HISTORIC = False
USE_LOCALHOST = False
ONLY_CHANGED_ALERTS = False
SEND_EMAIL = False
MIN_MISSING = 60  # 1 hours (60 mins) default missing alert
HIGHLIGHT_UNUSUAL = False
UNUSUAL_ONLY = False
REPORT_CARD = False
SNORKEL_DATA_URL = None

from config import config
import time
import urllib
import urllib2
import json

def post_to_snorkel(data):
  if not SNORKEL_DATA_URL:
    return

  if not 'integer' in data:
    data['integer'] = {}

  data['integer']['time'] = int(time.time())

  post_data = {
      "dataset": "super",
      "subset": "snitches",
      "samples": json.dumps([data])
  }
  post_data = urllib.urlencode(post_data)

  res = urllib2.urlopen(SNORKEL_DATA_URL, post_data)
  code = res.getcode()


def load_options():
  from optparse import OptionParser
  parser = OptionParser()
  parser.add_option("--local", dest="local", action="store_true")
  parser.add_option("--remote", dest="local", action="store_false")
  parser.add_option("--email", dest="email", action="store_true")
  parser.add_option("--history", dest="history", action="store_true")
  parser.add_option("--unusual", dest="unusual", action="store_true")
  parser.add_option("--changes", dest="changes", action="store_true")
  parser.add_option("--snorkel", dest="snorkel", action="store_true")

  parser.add_option("--report", dest="report", action="store_true")
  options, args = parser.parse_args()

  global USE_LOCALHOST, SEND_EMAIL, ONLY_CHANGED_ALERTS, PRINT_HISTORIC, SNORKEL_DATA_URL
  global HIGHLIGHT_UNUSUAL, UNUSUAL_ONLY
  global REPORT_CARD
  if options.local:
    USE_LOCALHOST = True

  if options.email:
    SEND_EMAIL = True

  if options.changes:
    ONLY_CHANGED_ALERTS = True

  if options.history:
    PRINT_HISTORIC = True

  if options.snorkel:
    SNORKEL_DATA_URL = True

  if options.unusual:
    UNUSUAL_ONLY = True

  if options.report:
    REPORT_CARD = True


def print_config():
  print "PRINTING HISTORIC: ", PRINT_HISTORIC
  print "QUERYING LOCALHOST: ", USE_LOCALHOST
  print "ONLY CHANGED ALERTS: ", ONLY_CHANGED_ALERTS
  print "SENDING EMAIL: ", SEND_EMAIL
  print "SENDING TO SNORKEL: ", SNORKEL_DATA_URL != None
  print ""


