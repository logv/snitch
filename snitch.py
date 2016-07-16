#!/usr/bin/env python

import json
import glob
import requests
import time
import time
import urllib
import urlparse
from collections import defaultdict

try:
    import configparser as CP
except:
    import ConfigParser as CP

try:
  import cPickle as pickle
except:
  import pickle


import config
SNORKEL_DATA_URL = config.SNORKEL_URL
USE_LOCALHOST=True
ONLY_CHANGED_ALERTS=False

def email_peoples(msg, body, to_notify):
  import emailer
  emailer.send_email(msg, body, to_notify)

def post_to_snorkel(data):
  if not SNORKEL_DATA_URL:
    return

  if not 'integer' in data:
    data['integer'] = {}

  data['integer']['time'] = int(time.time())

  post_data = {
    "dataset" : "super",
    "subset" : "snitches",
    "samples" : json.dumps([data])
  }
  post_data = urllib.urlencode(post_data)

  res = urllib2.urlopen(SNORKEL_DATA_URL, post_data)
  code = res.getcode()
 
def check_series(section, config):
  url = config.get(section, 'url', True) # reading in raw values because of %
  notify = config.get(section, 'notify')
  name = config.get(section, 'name')

  if url.find("http") != 0:
    url = "http://%s" % url


  parsed = urlparse.urlparse(url)
  host = parsed.netloc
  if USE_LOCALHOST:
    host = "localhost:3000"
  fixedquery = parsed.query.replace("view=weco", "view=time")
  new_url = (parsed.scheme, host, '/query/weco', parsed.params,
      fixedquery, parsed.fragment)
  geturl = urlparse.urlunparse(new_url)
  r = requests.get(geturl)

  try:
    code = r.status_code

    if code == 200 and r.text != "NOK":
      data = r.json()
      return data["violations"]

  except:
    
    return None

  # save the results to snorkel, quickly
  if code is not 200:
    print "site %s is down, sending email" % host
    return None
#    email_peoples("%s is down" % host, to_notify)


    

#  post_to_snorkel({
#    "string" : {
#      "host" : host,
#      "status" : code
#    }
#  })


# read our alarm files, then parse the results
# for a given alarm, we should figure out what our course of action is (remediation)
# we should also roll up all firing alarms into a single digest email
# ideally, we persist our list of alarm state to disk as well (or we query old alarm state?)


# TODO: 
# add spacing between queries so we dont destroy my server
# make an email with summaries
# backlog of past alerts
# * make sure we dont keep alerting on old alerts
# * highlight new ones
# * how do we know if we've recovered from an alert?
# figure out how often to check for alerts

def print_alert(alert_info):
  email_content = []
  ts = str(datetime.datetime.fromtimestamp(alert_info[0] / 1000))
  if alert_info[1]["type"] == "marker":
    return ""

  if "early" in alert_info[1] and alert_info[1]["early"]:
    line = "%s: EARLY WARNING (%s) %s" % (ts, alert_info[1]["type"], alert_info[1]["name"].strip())
  else:
    line = "%s: (%s) %s" % (ts, alert_info[1]["type"], alert_info[1]["name"].strip())

  email_content.append(line)
  now = time.mktime(time.localtime())
  start = alert_info[1]["value"]/1000
  if "recover_value" in alert_info[1]:
    start = alert_info[1]["recover_value"] / 1000
    now = alert_info[1]["value"] / 1000

  duration = (now - start) / 60.0
  duration_str = "m"
  if duration >= 60:
    duration /= 60
    duration_str = "h"

  ts = str(datetime.datetime.fromtimestamp(start))
  line = "%s: |_ duration: %.01f %s" % (ts, duration, duration_str)
  if "recover_type" in alert_info[1]:
    line = "%s: |_(%s) duration: %.02f %s" % (ts, alert_info[1]["recover_type"], duration, duration_str)
  email_content.append(line)

  return "\n".join(email_content)

import datetime
def violation_key(ts, series, type_name):
  value = datetime.datetime.fromtimestamp(ts/1000)

  args = tuple(map(lambda s: str(s).strip(), [ts, series, type_name]))
  return "%s:%s:%s" % args

def process_alerts():
  files = glob.glob("alarms/*.ini")

  all_violations = defaultdict(list)
  down_sections = []
  for f in files:
      with open(f) as of:
          config = CP.SafeConfigParser()
          config.optionxform = lambda x: str(x).lower()
          config.readfp(of)
          sections = config.sections()

          for section in sections:
              violations = check_series(section, config)
              if not violations:
                down_sections.append((f, section))
                continue

              all_violations[f].append((section, violations))



  violation_status = {}

  all_past = {}

  for f in all_violations:
    
    dbname = f.replace(".ini", ".p")
    past_violations = load_violations_from_disk(dbname)
    if past_violations:
      for v in past_violations:
        all_past[v] = past_violations[v]
    file_status = {}

    for section, violations in all_violations[f]:
      for v in violations:
        if "marker" in v and v["marker"]:
          continue

        alarm_file = f.replace("alarms/", "")

        if v["type"] == "recover":
          v["name"] = "%s:%s:%s" % (alarm_file, section, v["series"])
          vkey = violation_key(v["recover_value"], v["name"], v["recover_type"])
          if vkey in violation_status:
            violation_status[vkey] = v
            file_status[vkey] = v
        elif v["type"] != "marker":
          v["name"] = "%s:%s:%s" % (alarm_file, section, v["series"])
          vkey = violation_key(v["value"], v["name"], v["type"])
          violation_status[vkey] = v
          file_status[vkey] = v

    save_violations_to_disk(dbname, file_status, past_violations)

  return violation_status, all_past


def organize_and_print(violation_status, past_violations):
  new = []
  for k in violation_status:
    v = violation_status[k]
    pv = None
    if k in past_violations:
      pv = past_violations[k]

    if not pv or pv["type"] != v["type"]:
      new.append(v)
    elif ONLY_CHANGED_ALERTS:
      continue

    if "early" in v and v["early"]:
      earlies.append((v["value"], v))
      continue

    if not v["active"]:
      historic.append((v["value"], v)) 
      continue

    if v["type"] == "recover":
      recovered.append((v["value"], v)) 
    else:
      actives.append((v["value"], v))

  print "NEW VIOLATION STATUSES", len(new)

  earlies.sort(reverse=True)
  recovered.sort(reverse=True)
  actives.sort(reverse=True)
  historic.sort(reverse=True)

  email_content = [ ]
  if len(actives) > 0:
    email_content.append("ACTIVE ALERTS")
    email_content.append("-------------")

    for active in actives:
      email_content.append(print_alert(active))


  if len(earlies) > 0:
    email_content.append("\nEARLY ALERTS")
    email_content.append("----------------")
    for r in earlies:
      email_content.append(print_alert(r))
    

  if len(recovered) > 0:
    email_content.append("\nRECOVERED ALERTS")
    email_content.append("----------------")
    for r in recovered:
      email_content.append(print_alert(r))

  if len(historic) > 0:
    active = None
    email_content.append("\nHISTORIC ALERTS")
    email_content.append("----------------")
    for r in historic:
      email_content.append(print_alert(r))

  # need to decide about when to send the alerts and the alert digest.
  # i want to send digest once a day
  # i want to send active alerts regularly
  email_text = "\n".join(email_content)
  title = "snitch alerts [%s active]" % (len(actives))

  #    email_peoples(title, email_text, ["okay.zed@gmail.com"])
  if len(actives) == 0:
    print "NO ACTIVE ALERTS ALL IS WELL!"

  print email_text

def load_violations_from_disk(filename):
  try:
    return pickle.load(open(filename, "rb"))
  except:
    return {}

def save_violations_to_disk(filename, violations, past_violations):
  merged = {}

  for k in violations:
    merged[k] = violations[k]
  for k in past_violations:
    merged[k] = past_violations[k]

  pickle.dump(merged, open(filename, "wb" ) )

if __name__ == "__main__":
    earlies = []
    actives = []
    recovered = []
    historic = []

    violation_status, past_violations = process_alerts()
    organize_and_print(violation_status, past_violations)

