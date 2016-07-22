#!/usr/bin/env python

import glob
import math
import requests
import time
import sys
import urllib
import urllib2
import urlparse
import datetime
from collections import defaultdict

try:
  import configparser as CP
except:
  import ConfigParser as CP

import lib

from lib.util import violation_key, get_duration_str, localtz
from lib.diskio import load_violations_from_disk, save_violations_to_disk
from lib.emailer import email_peoples
from lib.stats import summarize_math
from lib.opts import post_to_snorkel

import lib.opts as opts

def check_series(section, config):
  url = config.get(section, 'url', True)  # reading in raw values because of %
  notify = config.get(section, 'notify')
  name = config.get(section, 'name')

  min_missing = opts.MIN_MISSING
  try:
    min_missing = int(config.get(section, 'alert_if_missing'))
  except CP.NoOptionError:
    pass

  end_buckets = 3
  try:
    end_buckets = int(config.get(section, "end_buckets"))
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
  if opts.USE_LOCALHOST:
    host = "localhost:3000"
  fixedquery = parsed.query.replace("view=weco", "view=time")
  new_url = (parsed.scheme, host, '/query/weco', parsed.params, fixedquery,
             parsed.fragment)
  geturl = urlparse.urlunparse(new_url)
  r = requests.get(geturl)

  violations = None
  data = None
  options = None

  try:
    code = r.status_code

    if code == 200 and r.text != "NOK":
      data = r.json()
      violations = data["violations"]
      valid_violations = []
    else:
      return None

  except:
    return None

  try:
    options = data["query"]["parsed"]
  except:
    pass

  print "missing time window for %s is %s mins" % (section, min_missing)
  for v in violations:
    v["url"] = url
    now = time.mktime(time.localtime())

    # TODO: set multiple "early" points per time series. for now, it is hardcoded
    # to be only one "safe zone" per time series
    if options:
      end_ms = options["end_ms"]
      time_bucket = options["time_bucket"]
      end_buckets = 3
      if "series" in v and v["time"] > end_ms - (time_bucket * end_buckets * 1000):
          ets = str(datetime.datetime.fromtimestamp(v["time"] / 1000, tz=localtz))[:-6]


          if v["type"] != "recover":
            print ets, "IGNORING ALERT AS EARLY", v["series"], v["type"]
            v["early"] = True
            continue
          else:
            print ets, "USING EARLY RECOVERY", v["series"], v["type"]

    if "recovery_type" in v and v["recovery_type"] == "missing":
      duration = (v["time"] - v["recovery_time"]) / 1000
    elif v["type"] == "missing" and v["active"]:
      duration = now - v["time"] / 1000
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

    start = v["recover_time"] / 1000
    now = v["time"] / 1000
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
  start = alert_info[1]["time"] / 1000
  if "recover_time" in alert_info[1]:
    start = alert_info[1]["recover_time"] / 1000
    now = alert_info[1]["time"] / 1000

  ts = str(datetime.datetime.fromtimestamp(now, tz=localtz))[:-6]
  type_str = "%s" % (alert_info[1]["type"])
  if "value" in alert_info[1]:
    type_str += " %.01f std" % alert_info[1]["value"]

  if "early" in alert_info[1] and alert_info[1]["early"]:
    line = "%s  EARLY WARNING (%s) %s" % \
      (ts, type_str, alert_info[1]["print_name"].strip())
  else:
    line = "%s  (%s) %s" % (ts, type_str, alert_info[1]["print_name"].strip())
    if "recover_type" in alert_info[1]:
      line = "%s  (recover) %s" % (ts, alert_info[1]["print_name"].strip())

  email_content.append(line)

  duration = (now - start)
  duration_str = get_duration_str(duration)

  sts = str(datetime.datetime.fromtimestamp(start, tz=localtz))[:-6]
  timepad = ''.join(map(lambda x: " ", sts))

  line = "%s  |_ duration: %s" % (sts, duration_str)
  if "recover_type" in alert_info[1]:
    type_str = "%s" % (alert_info[1]["recover_type"])
    if "recover_value" in alert_info[1]:
      type_str += " %.01f std" % alert_info[1]["recover_value"]

    line = "%s  |_ (%s) duration: %s" % (sts, type_str, duration_str)

  if similar_count > 0:
    std = duration_stats['std']
    mean = duration_stats['mean']
    if unusual_alert(alert_info, similar):
      gds = get_duration_str
      dmax = duration_stats['max']
      warnpad = list(timepad)
      for i, r in enumerate("   WARNING"):
        warnpad[i] = r

      warnpad = ''.join(warnpad)
      line += "\n%s  |_ longer than usual! cutoffs: %s, %s, %s" % (
          warnpad, gds(dmax), gds(mean + 2 * std), gds(mean + 3 * std))

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
    line += "\n%s  |_ new cutoffs: %s, %s, %s" % (timepad, gds(dmax),
                                                  gds(mean + 2 * std),
                                                  gds(mean + 3 * std))

  else:
    line += " prior unknown"

  email_content.append(line)

  return "\n".join(email_content)


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
            vkey = violation_key(v["recover_time"], v["name"],
                                 v["recover_type"])
            if vkey in violation_status:
              violation_status[vkey] = v
              file_status[vkey] = v
          elif v["type"] != "marker":
            v["print_name"] = "%s:%s" % (section, v["series"])
            v["name"] = "%s:%s:%s" % (alarm_file, section, v["series"])
            vkey = violation_key(v["time"], v["name"], v["type"])
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

        if opts.SEND_EMAIL:
          print "SENDING EMAIL TO", notify
          if opts.ONLY_CHANGED_ALERTS:
            title = "UPDATE: %s" % alarm_file
          else:
            title = "DIGEST: %s" % alarm_file

          email_peoples(title, content, notify)
      print ""


def find_similar(violation, past_violations, n=5):
  distances = []
  ts = datetime.datetime.fromtimestamp(violation[1]["time"] / 1000, tz=localtz)
  for pv in past_violations:
    if not "recover_time" in pv[1]:
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

    paststamp = pv[1]["recover_time"] / 1000
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
    return "UNSEEN"

  v = violation[1]
  for sarr in similar:
    s = sarr[-1]
    if not "recover_time" in s:
      similar_count -= 1
      continue

    start = s["recover_time"] / 1000
    now = s["time"] / 1000
    duration = now - start

    #  our  cutoff  for  similar  results   is   outages   less   than   1   day
    if duration > 60 * 60 * 24:
      similar_count -= 1
      continue

    similar_durations.append(duration)

  duration_stats, ok = summarize_math(similar_durations)

  now = time.mktime(time.localtime())
  start = violation[1]["time"] / 1000
  duration = now - start
  if "recover_time" in violation[1]:
    now = violation[1]["time"] / 1000
    start = violation[1]["recover_time"] / 1000
    duration = now - start

  if similar_count > 0:
    std = duration_stats['std']
    mean = duration_stats['mean']

    if (mean + 2 * std) < duration:
      return "BEAT 2x MEAN"

    if duration > duration_stats['max']:
      return "BEAT MAX"

    return False

  return "UNSEEN"


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
      historic.append((v["time"], v))
      continue

    # TODO: detect if this is an early warning or not, actually.
    if "early" in v and v["early"]:
      earlies.append((v["time"], v))
      continue

    if not pv or pv["type"] != v["type"]:
      new.append(v)
    elif opts.ONLY_CHANGED_ALERTS:
      if v["type"] != "recover":
        unchanged_active.append((v["time"], v))

      continue

    if v["type"] == "recover":
      recovered.append((v["time"], v))
    else:
      actives.append((v["time"], v))

  if len(unchanged_active) > 0:
    if opts.UNUSUAL_ONLY and opts.ONLY_CHANGED_ALERTS:
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

  new_actives = []
  new_recovered = []
  for active in actives:
    if opts.UNUSUAL_ONLY:
      if unusual_alert(active, historic):
        new_actives.append(active)
    else:
      new_actives.append(active)


  for r in recovered:
    if opts.UNUSUAL_ONLY:
      if unusual_alert(r, historic):
        new_recovered.append(r)
    else:
      new_recovered.append(r)

  email_content = []
  if len(new_actives) > 0:
    email_content.append("ACTIVE ALERTS %s" % alert_name)
    email_content.append("-------------")
    for active in new_actives:
      similar = find_similar(active, historic)
      email_content.append(print_alert(active, similar))

  if len(earlies) > 0:
    email_content.append("\nEARLY ALERTS %s" % alert_name)
    email_content.append("----------------")
    for r in earlies:
      similar = find_similar(r, historic)
      email_content.append(print_alert(r, similar))

  if len(new_recovered) > 0:
    email_content.append("\nRECENTLY RECOVERED %s" % alert_name)
    email_content.append("----------------")
    for r in recovered:
      similar = find_similar(r, historic)
      email_content.append(print_alert(r, similar))

  if opts.PRINT_HISTORIC and len(historic) > 0:
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


from config import config
def main():
  opts.load_options()


  if opts.SNORKEL_DATA_URL:
      opts.SNORKEL_DATA_URL = config.SNORKEL_URL

  opts.print_config()
  if opts.REPORT_CARD:
    import lib.report_card
    lib.report_card.process_report_card()
  else:
    start = time.mktime(time.localtime())
    process_alerts()
    end = time.mktime(time.localtime())
    print "CHECKING ALL ALERTS TOOK", end - start, "SECONDS"



if __name__ == "__main__":
  main()
