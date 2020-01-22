# Wildfire Milter
###### A milter interface to Wildfire Palo Alto API.

With this milter you can apply Wildfire malware analysis to mail flow.

The milter interfaces to Wildfire using API [as documented here](https://docs.paloaltonetworks.com/wildfire/9-0/wildfire-api.html).

This is a python milter pymilter based.
If a MIME mail part can be classified by Wildfire the sha256 hash is calculated and sent through RESTAPI to Wildfire.

The Wildfire accepted mime parts are listed in [AcceptedMIME] section of config file.
This list is based on official Wildfire manual, so take care if you want to change it.

A Wildfire verdict returns for every MIME attachments accepted for the analysis. The verdicts classes can be:

- clean
- suspicious
- threat

A suspicious result is a temporary state: it means that the part must be analyzed for a further definitive verdict.
The part is then submitted to Wildfire and in a couple of minutes a clean or threat verdict will be provided.
During this time you can choose to defer or accept the mail.

A threat state means that the mail contains dangerous content. You can choose to reject, defer, discard or accept the mail.
If you accept the dangerous mail an X header will be appended to highlight the infected content.

## Working details
The milter browses the mail parts looking for suitable MIME parts for analisys. If the part is an archive,
and the archive can't be analyzed by Wildfire, the file is recursively expanded to find out files which can be inspected.
All wildfire compliant files are kept in a list.

Patool is responsible for archive exapansion. This tool handles many archive types, much more than standard python libs can do.
But you must install the requested archive tools. Patool can raise some exceptions too. If this appens you will find the issue
in the log.

The milter send each hash of these files to Wildfire, to provide verdicts.
Hashes with clean or threat verdicts will be kept in a Redis cache by an asynchronous process or thread (at your choice).
Wildfire Milter relies on Redis Cache and asks to Wildfire only if hash can't be found on Redis.

If Wildfire returns a suspicious verdict, then the correspondent mime part will be sent to Wildfire for further analysis
using an asynchronous process or thread (at your choice).
Wildfire should return a specific code (-100) for already submitted sample. Anyway, a Redis cache of submitted samples
avoid resubmit.

Wildfire can change idea on verdicts. A scheduled script (`wfverdictchange.py`) can query all verdict changes
 and updates the Redis cache accordingly.

## Configurable behaviours
Notables configurable options:
- What to do on threats detection (Reject/Discard/Defer/Accept)
- The short message to return on milter Reject
- Detail to return on Reject message (part infected name and category of threat)
- Many logging options
- Chance to use thread or process for parallel task used for Redis write and Wildfire submit.
  Anyway, each connection uses a separate thread, as featured by pymilter.
- Calls to Wildfire can be optimized to make one call for all mime parts of a mail. All parts will be kept in memory,
  but you can preserve your daily quota. You can also choose to stop the analysis at the first threat found in the mail.
  These options could be useful or not, depending on your mail flow.
- A whitelist of envelope or files could be provided in the config file. If you find a false positive you should provide an
  API call to Wildfire to ask a verdict change. But you can also looking for the file hash in logs, and add that hash in
  the permanent whitelist.

## Installation
See at [INSTALL](INSTALL.md) instructions.

## Credits
- pymilter https://pymilter.org/pymilter/ by Stuart D. Gathman
- patool http://wummel.github.io/patool/ by wummel
- pan-python https://github.com/kevinsteves/pan-python by Kevin Steves
- redis-py https://pypi.org/project/redis/ by  Andy McCurdy
- python-magic https://github.com/ahupp/python-magic by Adam Hupp

Wildfire Milter has been inspired by:
- av-amavisd-new-wildfire of "nacho26":
    https://github.com/nacho26/av-amavisd-new-wildfire
- MacroMilter by Stephan Traub and Robert Scheck
    https://github.com/sbidy/MacroMilter