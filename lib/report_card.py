from collections import defaultdict

import glob
import time
import datetime

import diskio

from lib.util import violation_key, localtz, get_duration_str
from lib.stats import summarize_math
from lib.emailer import email_peoples

try:
  import configparser as CP
except:
  import ConfigParser as CP

def process_alert_for_report(v, durations, start_hours, active_hours):
  vname = v["name"] 
  if v["type"] == "recover":
    vkey = violation_key(v["recover_time"], v["name"],
                         v["recover_type"])

    duration = (v["time"] - v["recover_time"]) / 1000

    ts = datetime.datetime.fromtimestamp(v["recover_time"] / 1000, tz=localtz)
    hour = ts.hour
    start_hours[vname][ts.hour] += 1
    active_hours[vname][ts.hour] += 1

    if duration < 24 * 60 * 60:
      durations[vname].append(duration)

      while duration > 0:
        hour += 1
        hour %= 24
        duration -= 3600
        active_hours[vname][hour] += 1

def process_report_card():
  files = glob.glob("history/*.p")

  for f in files:
    ret = []

    past_violations = diskio.load_violations_from_disk(f)

    violation_status = {}
    unresolved = []
    types = defaultdict(list)

    durations = defaultdict(list)
    start_hours = defaultdict(lambda: [0] * 24)
    active_hours = defaultdict(lambda: [0] * 24)

    past_durations = defaultdict(list)
    past_start_hours = defaultdict(lambda: [0] * 24)
    past_active_hours = defaultdict(lambda: [0] * 24)

    way_past_durations = defaultdict(list)
    way_past_start_hours = defaultdict(lambda: [0] * 24)
    way_past_active_hours = defaultdict(lambda: [0] * 24)

    now = time.mktime(time.localtime())
    one_week = 60 * 60 * 24 * 7;
    time_cutoff = now - one_week
    last_week_cutoff = now - (one_week * 2)

    config = CP.SafeConfigParser()
    config.optionxform = lambda x: str(x).lower()
    with open(f.replace("history", "alarms").replace(".p", ".ini")) as of:
      config.readfp(of)
      notify = config.get("DEFAULT", "notify")


    if len(past_violations):
      ret.append("WEEK OVER WEEK SUMMARY FOR %s" % (f))
      ret.append("-----------------------------")




    for k in past_violations:
      v = past_violations[k]
      vname = v["name"]
      types[vname].append(v)
      violation_status[vname] = v

      if not "time" in v:
          continue

      if v["time"] > time_cutoff * 1000:
        process_alert_for_report(v, durations, start_hours, active_hours)

        if v["type"] != "marker" and v["type"] != "recover":
          vkey = violation_key(v["time"], v["name"], v["type"])
          unresolved.append(vkey)
      elif v["time"] > last_week_cutoff:
        process_alert_for_report(v, past_durations, past_start_hours, past_active_hours)
      else:
        process_alert_for_report(v, way_past_durations, way_past_start_hours, way_past_active_hours)


    # sum up the active hours for each dataset
    alert_arr = types.keys()
    alert_arr.sort(key=lambda t: sum(past_active_hours[t]) - sum(active_hours[t]) )

    for t in alert_arr:
      similar = types[t]
      duration_stats, ok = summarize_math(durations[t])

      format_args = [len(durations[t])]
      mean = duration_stats['mean']
      std = duration_stats['std']
      dmax = duration_stats['max']

      for val in (duration_stats['mean'], duration_stats['min'],
                  duration_stats['max'], duration_stats['std']):
        format_args.append(get_duration_str(val))

      gds = get_duration_str
 
      fname = f.replace("p", "ini").replace("history/", "") + ":"
      begin_str = ""
      for c in start_hours[t]:
        begin_str += "%-02i " % c if c != 0 else "   "

      alive_str = ""
      for c in active_hours[t]:
        alive_str += "%-02i " % c if c != 0 else "   "

      past_active = ""
      for c in past_active_hours[t]:
        past_active += "%-02i " % c if c != 0 else "   "

      past_begin = ""
      for c in past_start_hours[t]:
        past_begin += "%-02i " % c if c != 0 else "   "

      ret.append("%s" % (t.replace(fname, "")))
      if len(durations[t]) > 0:
        sum_active = sum(active_hours[t])
        past_sum_active = sum(past_active_hours[t])

        ret.append("|_ count: %s avg: %s, min: %s, max: %s, std: %s" % tuple(format_args))
        ret.append("|_ active hours: %s, last week: %s, delta: %s" % (sum_active, past_sum_active, sum_active - past_sum_active))
        ret.append("|_ cutoffs: %s, %s, %s" % (gds(dmax), gds(mean + 2 * std), gds(mean + 3 * std)))
        ret.append("|_    begin: " + begin_str)
        ret.append("|_    alive: " + alive_str)
        ret.append("|_    hours: " + "|".join(map(lambda x: "%02i" % x, range(0, 24))))
        ret.append("|_ p. alive: " + past_active)
        ret.append("|_ p. begin: " + past_begin)
        ret.append("")
      else:
        ret.append("NO ALERTS!")
        ret.append("")

    content = "\n".join(ret)
    title = "WEEKLY REPORT CARD: %s" % (f)
    email_peoples(title, content, notify)
    print content


