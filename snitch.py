#!/usr/bin/env python

import json
import glob
import math
import requests
import time
import sys
import urllib
import urllib2
import urlparse
import datetime
from dateutil.tz import tzoffset

from collections import defaultdict

localtz = tzoffset("PST", -25200)

try:
  import configparser as CP
except:
  import ConfigParser as CP

try:
  import cPickle as pickle
except:
  import pickle

import lib
from config import config
SNORKEL_DATA_URL = None

PRINT_HISTORIC = False
USE_LOCALHOST = False
ONLY_CHANGED_ALERTS = False
SEND_EMAIL = False
MIN_MISSING = 60  # 1 hours (60 mins) default missing alert
HIGHLIGHT_UNUSUAL = False
UNUSUAL_ONLY = False


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
  options, args = parser.parse_args()

  global USE_LOCALHOST, SEND_EMAIL, ONLY_CHANGED_ALERTS, PRINT_HISTORIC, SNORKEL_DATA_URL
  global HIGHLIGHT_UNUSUAL, UNUSUAL_ONLY
  if options.local:
    USE_LOCALHOST = True

  if options.email:
    SEND_EMAIL = True

  if options.changes:
    ONLY_CHANGED_ALERTS = True

  if options.history:
    PRINT_HISTORIC = True

  if options.snorkel:
    SNORKEL_DATA_URL = config.SNORKEL_URL

  if options.unusual:
    UNUSUAL_ONLY = True


def print_config():
  print "PRINTING HISTORIC: ", PRINT_HISTORIC
  print "QUERYING LOCALHOST: ", USE_LOCALHOST
  print "ONLY CHANGED ALERTS: ", ONLY_CHANGED_ALERTS
  print "SENDING EMAIL: ", SEND_EMAIL
  print "SENDING TO SNORKEL: ", SNORKEL_DATA_URL != None
  print ""


def email_peoples(msg, body, to_notify):
  if isinstance(to_notify, str):
    to_notify = [to_notify]
  if SEND_EMAIL:
    print "SENDING EMAIL"
    import lib.emailer
    lib.emailer.send_email(msg, body, to_notify)


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


def summarize_math(arr):
  math_stats = defaultdict(lambda: defaultdict(int))
  all_stats = defaultdict(int)

  def initialize_stats(stats_dict):
    stats_dict['min'] = sys.maxint
    stats_dict['max'] = -sys.maxint + 1
    stats_dict['vals'] = []

  def update_stats(stats_dict, val):
    stats_dict['count'] += 1
    stats_dict['max'] = max(stats_dict['max'], val)
    stats_dict['min'] = min(stats_dict['min'], val)
    stats_dict['sum'] += val
    stats_dict['vals'].append(val)

  def finalize_stats(stats_dict):
    if stats_dict['count'] is 0:
      return False

    mean = stats_dict['mean'] = stats_dict['sum'] / stats_dict['count']
    stats_dict['vals'].sort()
    error = 0
    for val in stats_dict['vals']:
      error += abs(mean - val)**2

    error /= stats_dict['count']
    std = math.sqrt(error)

    stats_dict['big5'] = get_five(stats_dict)
    stats_dict['std'] = std

    return True

  def get_five(stats_dict):
    vals = stats_dict['vals']
    length = len(vals)
    return {
        "5": vals[int(length * 0.05)],
        "25": vals[int(length * 0.25)],
        "50": vals[int(length * 0.50)],
        "75": vals[int(length * 0.75)],
        "95": vals[int(length * 0.95)]
    }

  initialize_stats(all_stats)

  for val in arr:
    update_stats(all_stats, val)

    # test the token to see if its numbery. if so... modify it

  has_stats = finalize_stats(all_stats)

  return all_stats, has_stats


def check_series(section, config):
  url = config.get(section, 'url', True)  # reading in raw values because of %
  notify = config.get(section, 'notify')
  name = config.get(section, 'name')

  min_missing = MIN_MISSING
  try:
    min_missing = int(config.get(section, 'alert_if_missing'))
  except CP.NoOptionError:
    pass

  # if the section is disabled, we dont run these alerts
  try:
    disabled = config.get(section, 'disabled')
    if disabled:
      print "skipping disabled section", section
      return None
  except CP.NoOptionError:
    pass

  if url.find("http") != 0:
    url = "http://%s" % url

  parsed = urlparse.urlparse(url)
  host = parsed.netloc
  if USE_LOCALHOST:
    host = "localhost:3000"
  fixedquery = parsed.query.replace("view=weco", "view=time")
  new_url = (parsed.scheme, host, '/query/weco', parsed.params, fixedquery,
             parsed.fragment)
  geturl = urlparse.urlunparse(new_url)
  r = requests.get(geturl)

  violations = None
  try:
    code = r.status_code

    if code == 200 and r.text != "NOK":
      data = r.json()
      violations = data["violations"]
      valid_violations = []

  except:
    return None

  print "missing time window for %s is %s mins" % (section, min_missing)
  for v in violations:
    v["url"] = url
    now = time.mktime(time.localtime())
    if "recovery_type" in v and v["recovery_type"] == "missing":
      duration = (v["value"] - v["recovery_value"]) / 1000
    elif v["type"] == "missing" and v["active"]:
      duration = now - v["value"] / 1000
    else:
      valid_violations.append(v)
      continue

    duration /= 60
    if duration >= min_missing:
      valid_violations.append(v)
    else:
      print "IGNORING MISSING VIOLATION, TOO SMALL: %s" % (v["series"])

  return valid_violations

  # save the results to snorkel, quickly
  if code is not 200:
    print "site %s is down, sending email" % host
    title = "%s is down" % host
    body = "Couldnt not run alarms in %s" % name
    email_peoples(title, body, notify)
    return None

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
# figure out how often to check for alerts (every 30 minutes works for me)


def get_duration_str(d):
  d_str = "m"
  d /= 60
  if d >= 60:
    d /= 60
    d_str = "h"

  return "%.02f%s" % (d, d_str)


def print_alert(alert_info, similar=[]):
  email_content = []
  if alert_info[1]["type"] == "marker":
    return ""

  total_dur = 0
  similar_count = len(similar)
  hour_similar = 0
  day_similar = 0
  common = 0

  similar_durations = []
  for s in similar:
    hour_diff, weekday_diff, v = s

    start = v["recover_value"] / 1000
    now = v["value"] / 1000
    duration = now - start

    # our cutoff for similar results is outages less than 1 day
    if duration > 60 * 60 * 24:
      similar_count -= 1
      continue

    used = 0
    similar_durations.append(duration)

    if hour_diff < 2:
      hour_similar += 1
      used += 1
    if weekday_diff == 0:
      day_similar += 1
      used += 1

    if not used:
      similar_count -= 1
    else:
      total_dur += duration

    if used == 2:
      common += 1

  duration_stats, ok = summarize_math(similar_durations)
  similar_str = "???"
  if hour_similar > 0 and day_similar > 0:
    similar_str = "similar: %s by hour, %s by day, total: %s" % (
        hour_similar, day_similar, hour_similar + day_similar - common)
  elif hour_similar > 0:
    similar_str = "similar: %s by hour" % hour_similar
  elif day_similar > 0:
    similar_str = "similar: %s by day" % day_similar

  avg_dur = float(total_dur) / (similar_count or 1)
  avg_dur_str = get_duration_str(avg_dur)
  if similar_count == 0:
    avg_dur_str = "???"

  now = time.mktime(time.localtime())
  start = alert_info[1]["value"] / 1000
  if "recover_value" in alert_info[1]:
    start = alert_info[1]["recover_value"] / 1000
    now = alert_info[1]["value"] / 1000

  ts = str(datetime.datetime.fromtimestamp(now, tz=localtz))[:-6]
  if "early" in alert_info[1] and alert_info[1]["early"]:
    line = "%s  EARLY WARNING (%s) %s" % \
      (ts, alert_info[1]["type"], alert_info[1]["print_name"].strip())
  else:
    line = "%s  (%s) %s" % (ts, alert_info[1]["type"],
                            alert_info[1]["print_name"].strip())
    if "recover_type" in alert_info[1]:
      line = "%s  (recover) %s" % (ts, alert_info[1]["print_name"].strip())

  email_content.append(line)

  duration = (now - start)
  duration_str = get_duration_str(duration)

  sts = str(datetime.datetime.fromtimestamp(start, tz=localtz))[:-6]
  timepad = ''.join(map(lambda x: " ", sts))

  line = "%s  |_ duration: %s" % (sts, duration_str)
  if "recover_type" in alert_info[1]:
    line = "%s  |_ (%s) duration: %s" % (sts, alert_info[1]["recover_type"],
                                         duration_str)

  if similar_count > 0:
    std = duration_stats['std']
    mean = duration_stats['mean']
    if duration_stats['mean'] + 2 * std < duration:
      gds = get_duration_str
      dmax = duration_stats['max']
      line += "\n%s  |_ WARNING: longer than usual! cutoffs: %s, %s, %s" % (
          timepad, gds(dmax), gds(mean + 2 * std), gds(mean + 3 * std))

    line += "\n%s  |_ prior %s" % (timepad, similar_str)
    format_args = [timepad]
    for val in (duration_stats['mean'], duration_stats['min'],
                duration_stats['max'], duration_stats['std']):
      format_args.append(get_duration_str(val))
    line += "\n%s  |_ prior avg: %s, min: %s, max: %s, std: %s" % tuple(
        format_args)

    similar_durations.append(duration)
    duration_stats, ok = summarize_math(similar_durations)
    format_args = [timepad]
    for val in (duration_stats['mean'], duration_stats['min'],
                duration_stats['max'], duration_stats['std']):
      format_args.append(get_duration_str(val))
    line += "\n%s  |_ adjust avg: %s, min: %s, max: %s, std: %s" % tuple(
        format_args)
    gds = get_duration_str

    mean = duration_stats['mean']
    std = duration_stats['std']
    dmax = max(duration_stats['max'], duration)
    line += "\n%s  |_ new cutoffs: %s, %s, %s" % (
        timepad, gds(dmax), gds(mean + 2 * std), gds(mean + 3 * std))

  else:
    line += " prior unknown"

  email_content.append(line)

  return "\n".join(email_content)


def violation_key(ts, series, type_name):
  value = datetime.datetime.fromtimestamp(ts / 1000, tz=localtz)

  args = tuple(map(lambda s: str(s).strip(), [ts, series, type_name]))
  return "%s:%s:%s" % args


def process_alerts():
  files = glob.glob("alarms/*.ini")

  all_violations = defaultdict(list)
  down_sections = []
  alerted = 0
  for f in files:
    with open(f) as of:
      config = CP.SafeConfigParser()
      config.optionxform = lambda x: str(x).lower()
      config.readfp(of)
      sections = config.sections()

      start = time.mktime(time.localtime())
      notify = config.get("DEFAULT", "notify")

      print "----", f
      for section in sections:
        violations = check_series(section, config)
        if not violations:
          down_sections.append((f, section))
          continue

        early_warnings = False
        try:
          early_warnings = config.get(section, 'early_warnings')
        except CP.NoOptionError:
          pass

        if not early_warnings:
          violations = filter(lambda x: "early" not in x or x["early"] == False,
                              violations)

        all_violations[f].append((section, violations))

      # PREPARE FILE LEVEL CONTENT
      violation_status = {}

      dbname = f.replace("alarms/", "history/").replace(".ini", ".p")
      past_violations = load_violations_from_disk(dbname)
      file_status = {}
      file_urls = {}

      alarm_file = f.replace("alarms/", "")

      for section, violations in all_violations[f]:
        for v in violations:
          if "marker" in v and v["marker"]:
            continue

          if "url" in v:
            file_urls[v["url"]] = True

          if v["type"] == "recover":
            v["print_name"] = "%s:%s" % (section, v["series"])
            v["name"] = "%s:%s:%s" % (alarm_file, section, v["series"])
            vkey = violation_key(v["recover_value"], v["name"],
                                 v["recover_type"])
            if vkey in violation_status:
              violation_status[vkey] = v
              file_status[vkey] = v
          elif v["type"] != "marker":
            v["print_name"] = "%s:%s" % (section, v["series"])
            v["name"] = "%s:%s:%s" % (alarm_file, section, v["series"])
            vkey = violation_key(v["value"], v["name"], v["type"])
            violation_status[vkey] = v
            file_status[vkey] = v
        now = time.mktime(time.localtime())
        print section, "took", now - start

      save_violations_to_disk(dbname, file_status, past_violations)
      content = organize_email(file_status, past_violations, alarm_file)
      end = time.mktime(time.localtime())
      duration = end - start

      now = time.mktime(time.localtime())
      print "----", f, "took", now - start
      alerted += 1
      if content:
        print ""
        print content
        print ""

        urls = file_urls.keys()
        content = "%s\n\nURLS:\n%s" % (content, "\n* ".join(urls))

        if SEND_EMAIL:
          print "SENDING EMAIL TO", notify
          if ONLY_CHANGED_ALERTS:
            title = "UPDATE: %s" % alarm_file
          else:
            title = "DIGEST: %s" % alarm_file

          email_peoples(title, content, notify)
      print ""


def find_similar(violation, past_violations, n=5):
  distances = []
  ts = datetime.datetime.fromtimestamp(violation[1]["value"] / 1000, tz=localtz)
  for pv in past_violations:
    if not "recover_value" in pv[1]:
      continue

    if pv[1] == violation[1]:
      continue

    if pv[1]["name"] != violation[1]["name"]:
      continue

    recovery_matches_type = pv[1]["recover_type"] == violation[1]["type"]
    if "recover_type" in violation[1]:
      recovery_matches_recovery = pv[1]["recover_type"] == violation[1][
          "recover_type"]
      if not recovery_matches_recovery and not recovery_matches_type:
        continue
    elif not recovery_matches_type:
      continue

    paststamp = pv[1]["recover_value"] / 1000
    ps = datetime.datetime.fromtimestamp(paststamp, tz=localtz)

    hour_diff = abs(ts.hour - ps.hour)
    if hour_diff >= 12:
      hour_diff = abs(24 + ts.hour - ps.hour) % 24

    # we lump stuff in buckets of 3 hours
    hour_diff /= 3

    weekday_diff = abs(ts.weekday() - ps.weekday()) * 3

    diff = math.sqrt(hour_diff**2 + weekday_diff**2)

    if hour_diff <= 2 or weekday_diff <= 2:
      distances.append((hour_diff, weekday_diff, pv[1]))

  distances.sort()
  return distances[:n]


def unusual_alert(violation, similar):
  similar_durations = []
  similar_count = len(similar)
  if len(similar) == 0:
    return

  v = violation[1]
  for s in similar:
    if not "recover_value" in similar:
      continue

    start = v["recover_value"] / 1000
    now = v["value"] / 1000
    duration = now - start

    # our cutoff for similar results is outages less than 1 day
    if duration > 60 * 60 * 24:
      similar_count -= 1
      continue

    similar_durations.append(duration)

  duration_stats, ok = summarize_math(similar_durations)

  now = time.mktime(time.localtime())
  start = violation[1]["value"] / 1000
  duration = now - start

  if similar_count > 0:
    std = duration_stats['std']
    mean = duration_stats['mean']

    if (mean + 2 * std) < duration:
      return True

    if duration > duration_stats['max']:
      return True

  return False


def organize_email(violation_status, past_violations, alert_name):
  new = []
  earlies = []
  actives = []
  recovered = []
  historic = []
  unchanged_active = []

  for k in violation_status:
    v = violation_status[k]
    pv = None
    if k in past_violations:
      pv = past_violations[k]

    if not v["active"]:
      historic.append((v["value"], v))
      continue

    if not pv or pv["type"] != v["type"]:
      new.append(v)
    elif ONLY_CHANGED_ALERTS:
      if v["type"] != "recover":
        unchanged_active.append((v["value"], v))

      continue

    if "early" in v and v["early"]:
      earlies.append((v["value"], v))
      continue

    if v["type"] == "recover":
      recovered.append((v["value"], v))
    else:
      actives.append((v["value"], v))

  if len(unchanged_active) > 0:
    if UNUSUAL_ONLY and ONLY_CHANGED_ALERTS:
      for alert in unchanged_active:
        similar = find_similar(alert, historic)
        if unusual_alert(alert, similar):
          actives.append(alert)

      remove = []
      for alert in actives:
        similar = find_similar(alert, historic)
        if similar and not unusual_alert(alert, similar):
          remove.append(alert)

      for r in remove:
        actives.remove(r)

  unchanged_active.sort(reverse=True)
  earlies.sort(reverse=True)
  recovered.sort(reverse=True)
  actives.sort(reverse=True)

  historic.sort(reverse=True)

  post_to_snorkel({
      "string": {
          "name": alert_name,
      },
      "integer": {
          "new": len(new),
          "active": len(actives),
          "unchanged": len(unchanged_active),
          "recovered": len(recovered),
          "historic": len(historic),
          "early": len(earlies)
      }
  })

  email_content = []
  if len(actives) > 0:
    email_content.append("ACTIVE ALERTS %s" % alert_name)
    email_content.append("-------------")

    for active in actives:
      similar = find_similar(active, historic)
      if UNUSUAL_ONLY:
        if unusual_alert(active, historic):
          email_content.append(print_alert(active, similar))
      else:
        email_content.append(print_alert(active, similar))

  if len(earlies) > 0:
    email_content.append("\nEARLY ALERTS %s" % alert_name)
    email_content.append("----------------")
    for r in earlies:
      similar = find_similar(r, historic)
      email_content.append(print_alert(r, similar))

  if len(recovered) > 0:
    email_content.append("\nRECENTLY RECOVERED %s" % alert_name)
    email_content.append("----------------")
    for r in recovered:
      similar = find_similar(r, historic)
      email_content.append(print_alert(r, similar))

  if PRINT_HISTORIC and len(historic) > 0:
    active = None
    email_content.append("\nHISTORIC ALERTS %s" % alert_name)
    email_content.append("----------------")
    for r in historic:
      similar = find_similar(r, historic)
      email_content.append(print_alert(r, similar))

  # need to decide about when to send the alerts and the alert digest.
  # i want to send digest once a day
  # i want to send active alerts regularly
  email_text = "\n".join(email_content)
  return email_text


def load_violations_from_disk(filename):
  try:
    ret = pickle.load(open(filename, "rb"))
    return ret
  except:
    return {}


def save_violations_to_disk(filename, violations, past_violations):
  merged = {}

  for k in past_violations:
    merged[k] = past_violations[k]
  for k in violations:
    merged[k] = violations[k]

  pickle.dump(merged, open(filename, "wb"))


def main():
  load_options()
  print_config()
  start = time.mktime(time.localtime())
  alerted = process_alerts()
  end = time.mktime(time.localtime())
  print "CHECKING ALL ALERTS TOOK", end - start, "SECONDS"


if __name__ == "__main__":
  main()
