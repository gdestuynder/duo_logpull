#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
sys.path.append('duo_client')

cfg_path = ['duo_logpull.conf']
config = None

for cfg in cfg_path:
    if os.path.isfile(cfg):
        try:
            config = imp.load_source('config', cfg)
        except:
            pass

if config == None:
    print("Failed to load config")
    sys.exit(1)

import duo_client
import mozdef
import time
from datetime import datetime
import pytz
import json
import pickle


duo = duo_client.Admin(ikey=config.IKEY, skey=config.SKEY, host=config.URL)
mozmsg = mozdef.MozDefMsg(config.MOZDEF_URL, tags=['duosecurity', 'logs'])
mozmsg.debug = config.DEBUG

def process_events(duo_events, etype, state):
    # There are some key fields that we use as MozDef fields, those are set to "noconsume"
    # After processing these fields, we just pour everything into the "details" fields of Mozdef, except for the
    # noconsume fields.

    if etype == 'administration':
        noconsume = ['timestamp', 'host', 'action']
    elif etype == 'telephony':
        noconsume = ['timestamp', 'host', 'context']
    elif etype == 'authentication':
        noconsume = ['timestamp', 'host', 'eventtype']
    else:
        return

    for e in duo_events:
        details = {}
        mozmsg.log['timestamp'] = pytz.timezone('UTC').localize(datetime.utcfromtimestamp(e['timestamp'])).isoformat()
        mozmsg.log['hostname'] = e['host']
        for i in e:
            if i in noconsume:
                continue

    # Duo client doesn't translate inner dicts to dicts for some reason - its just a string, so we have to process and parse it
            if e[i] != None and type(e[i]) == str and  e[i].startswith('{'):
                j = json.loads(e[i])
                for x in j:
                    details[x] = j[x]
                continue

            details[i] = e[i]
        if etype == 'administration':
          mozmsg.send(e['action'], details=details)
        elif etype == 'telephony':
          mozmsg.send(e['context'], details=details)
        elif etype == 'authentication':
          mozmsg.send(e['eventtype']+' '+e['result']+' for '+e['username'], details=details)

    # last event timestamp record is stored and returned so that we can save our last position in the log.
    try:
        state[etype] = e['timestamp']
    except UnboundLocalError:
        # duo_events was empty, no new event
        pass
    return state


if __name__ == "__main__":
    try:
        state = pickle.load(open(config.statepath, 'rb'))
    except IOError:
        # Oh, you're new.
        state = {'administration': 0, 'authentication': 0, 'telephony': 0}

    # This will process events for all 3 log types and send them to MozDef. the state stores the last position in the
    # log when this script was last called.
    state = process_events(duo.get_administrator_log(mintime=state['administration']+1), 'administration', state)
    state = process_events(duo.get_authentication_log(mintime=state['authentication']+1), 'authentication', state)
    state = process_events(duo.get_telephony_log(mintime=state['telephony']+1), 'telephony', state)

    pickle.dump(state, open(config.statepath, 'wb'))
