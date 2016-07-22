try:
  import cPickle as pickle
except:
  import pickle

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

