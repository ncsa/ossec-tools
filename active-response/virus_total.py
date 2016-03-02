#!/usr/bin/env python
import json
import urllib
import urllib2
import sys

apikey = '843fa2012b619be746ead785b933d59820a2e357c7c186e581e8fcadbe2e550e'

def usage():
  print '''Submit hash to virtus-total
(Place your VirusTotal apikey in this script)
Usage: %s <hash>''' % sys.argv[0]
  exit(1)

def collect(data):
  retrieve             = data[0]
  sha1                 = retrieve['sha1']
  filenames            = retrieve['filenames']
  first_seen           = retrieve['first-seen']
  last_seen            = retrieve['last-seen']
  last_scan_permalink  = retrieve['last-scan-permalink']
  last_scan_report     = retrieve['last-scan-report']
  return sha1, filenames, first_seen, last_seen, last_scan_permalink, last_scan_report

def msg(sha1, filenames, first_seen, last_seen, last_scan_permalink):
  print '''===Suspected Malware Item===
  SHA1: %s
  Filenames: %s
  First Seen: %s
  Last Seen: %s
  Link: %s''' % (sha1, filenames, first_seen, last_seen, last_scan_permalink)

def is_malware(last_scan_report):
  for av, scan in last_scan_report.iteritems():
    if scan[0] is not None:
      return True
  return False

def in_database(data, mhash):
  result = data[0]['result']
  if result == 0: 
    return False
  return True

def arguments():
  if len(sys.argv) < 2:
    usage()
  if '-h' in sys.argv[1]:
    usage()
  if not apikey:
    print "Set apikey in %s to value of your Virus Total key" % sys.argv[0]
    exit(1)

  mhash = sys.argv[1]
  return mhash

def query_api(mhash, apikey):
  url = "http://api.vtapi.net/vtapi/get_file_infos.json"
  parameters = {"resources": mhash, "apikey": apikey}
  encoded = urllib.urlencode(parameters)
  req = urllib2.Request(url, encoded)
  response = urllib2.urlopen(req)
  response_string = response.read()
  data = json.loads(response_string)
  return data

mhash = arguments()
data = query_api(mhash, apikey)

if not in_database(data, mhash):
  print 'No entry for %s in database' % mhash
  exit(1)

# Positive match found
sha1, filenames, first_seen, last_seen, last_scan_permalink, last_scan_report = collect(data)
if is_malware(last_scan_report):
  msg(sha1, filenames, first_seen, last_seen, last_scan_permalink)
  exit(0)
else:
  print 'Entry %s is not malicious' % mhash
  exit(1)
