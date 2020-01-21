#!/usr/bin/env python3
import sys
from datetime import date, timedelta

import pan.wfapi
import os
import redis
from WildfireMilter.wildlib import load_yaml

## Config
CONFIG = os.path.join(os.path.dirname("/etc/wildfire-milter/"), "milter.conf")
if not os.path.isfile(CONFIG):
    # developing stage
    CONFIG = os.path.join(os.path.dirname(__file__), "WildfireMilter/etc/milter.conf")

if not os.path.isfile(CONFIG):
    # Try to copy dist file in first config file
    distconf = os.path.join(os.path.dirname(CONFIG), "milter.conf.dist")
    if os.path.isfile(distconf):
        print("First run? I don't find <milter.conf>, but <milter.conf.dist> exists. I try to rename it.")
        os.rename(distconf, os.path.join(os.path.dirname(distconf), "milter.conf"))

# get the configuration items
if os.path.isfile(CONFIG):
    redis_parameters = load_yaml(CONFIG, "Redis")
    wild_parameters = load_yaml(CONFIG, "Wildfire")

redishost = redis_parameters['HOST']
redisport = redis_parameters['PORT']
redisauth = redis_parameters['AUTH']
redisdb = redis_parameters['DB']

apikey = wild_parameters['KEY']
apihost = wild_parameters['HOST']

# Looking from <delta> days ago
delta = 1
ttl = redis_parameters['TTL']
####

try:
    wfapi = pan.wfapi.PanWFapi(
        tag='wildfire',
        api_key=apikey,
        hostname=apihost
    )

except pan.wfapi.PanWFapiError as msg:
    print('pan.wfapi.PanWFapi:', msg, file=sys.stderr)
    sys.exit(1)

try:
   r = redis.StrictRedis(host=redishost, port=redisport, db=redisdb, password=redisauth)
   r.ping()

except redis.ConnectionError as e:
            print('Can not connect to Redis on ' + redishost + ': ' + repr(e))
            sys.exit(1)

print ("======== Redis Verdict Change Updater ========\n")
try:
    kwargs = {}
    if delta > 0:
        d = date.today()
        d = d - timedelta(delta)
        kwargs["date"] = d.isoformat()

    wfapi.verdicts_changed(**kwargs)
    if wfapi.xml_element_root is None:
       sys.exit(0)

    elem = wfapi.xml_element_root
    nelem = len(wfapi.xml_element_root.getchildren())
    print("Changed verdicts from %s: %d" % (kwargs["date"],nelem), file=sys.stderr)
    cont = 0

    for child in elem:
       for verdict in child:
           if verdict.tag == 'sha256':
               key = verdict.text
           if verdict.tag == 'verdict':
               kvalue = verdict.text
               try:
                  result = r.set(key, kvalue, ex=86400, nx=False, xx=True)
                  if result is True:
                     print("key=<%s> newvalue=<%s> result=<%s>" % (key, kvalue, result))
                     cont = cont +1
                  if result is False:
                     print("key=<%s> newvalue=<%s> result=<%s>" % (key, kvalue, result))
                  if result is None:
                     pass

               except redis.RedisError as err:
                  print('Redis Error: key=%s value=%s err=%s' % (key, kvalue, err), file=sys.stderr)

    print("\n%d keys changed in Redis Cache." % cont)

except pan.wfapi.PanWFapiError as msg:
    print('main:', msg, file=sys.stderr)
    sys.exit(1)

print("================ Normal  exit ================")
sys.exit(0)
