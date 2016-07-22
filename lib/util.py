import datetime

from dateutil.tz import tzoffset

localtz = tzoffset("PST", -25200)

def violation_key(ts, series, type_name):
  value = datetime.datetime.fromtimestamp(ts / 1000, tz=localtz)

  args = tuple(map(lambda s: str(s).strip(), [ts, series, type_name]))
  return "%s:%s:%s" % args


def get_duration_str(d):
  d_str = "m"
  d /= 60
  if d >= 60:
    d /= 60
    d_str = "h"

  return "%.02f%s" % (d, d_str)

