from collections import defaultdict

import math
import sys

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


