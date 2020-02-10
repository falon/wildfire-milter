#!/usr/bin/env python3
############################################################################
#
# Falon entertainment presents:
#      *** Wildfire Milter for Postfix ***
#      https://github.com/falon/wildfire-milter
#
# Inspired by
#
# - av-amavisd-new-wildfire by "nacho26":
#     https://github.com/nacho26/av-amavisd-new-wildfire
# - MacroMilter by Stephan Traub - Sbidy and Robert Scheck - robert-scheck
#     https://github.com/sbidy/MacroMilter
#
# Credits:
#
# - pymilter https://pythonhosted.org/pymilter/ by Stuart D. Gathman
# - patool http://wummel.github.io/patool/ by wummel
# - pan-python https://github.com/kevinsteves/pan-python by Kevin Steves
# - redis-py https://pypi.org/project/redis/ by  Andy McCurdy
# - python-magic https://github.com/ahupp/python-magic by Adam Hupp
#
# TODO: handle exception if milter SOCKET can't open.
# TODO: manage config reload without milter restart.
# TODO: add systemd notify
# TODO: add check of url in text parts.
#
############################################################################
import codecs
import email
import logging
import logging.handlers
import os
import signal
import sys
import time
from io import BytesIO
from pathlib import Path
from socket import AF_INET6

import Milter
from Milter.utils import parse_addr

import WildfireMilter.wildlib as wildlib

## Config
__version__ = '0.1'  # version
# get the config from FHS conform dir
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
    milter_parameters = wildlib.load_yaml(CONFIG, "Milter")
    SOCKET = milter_parameters['SOCKET']
    try:
        UMASK = int(milter_parameters['UMASK'], base=0)
    except:
        UMASK = 0o0077
    TIMEOUT = milter_parameters['TIMEOUT']
    MESSAGE = milter_parameters['MESSAGE']
    DEFER = milter_parameters['DEFER_IF_SUSPECT']
    MAX_NESTED_ARCHIVE = milter_parameters['MAX_NESTED']
    MILTER_RETURN = milter_parameters['ON_VIRUS']
    REJECT_DETAIL = milter_parameters['REJECT_DETAIL']

    logging_parameters =  wildlib.load_yaml(CONFIG, "Logging")
    LOGFILE_DIR = logging_parameters['LOGFILE_DIR']
    LOGFILE_NAME = logging_parameters['LOGFILE_NAME']
    LOGSTDOUT = logging_parameters['LOGSTDOUT']
    LOGHANDLER = logging_parameters['TYPE']
    SYSLOG_FAC = logging_parameters['SYSLOG_FAC']
    SYSLOG_LEVEL = logging_parameters['LOG_LEVEL']
    SYSLOG_SOCKET = logging_parameters['SYSLOG_SOCKET']

    redis_parameters =  wildlib.load_yaml(CONFIG, "Redis")
    REDISHOST = redis_parameters['HOST']
    REDISPORT = redis_parameters['PORT']
    REDISAUTH = redis_parameters['AUTH']
    REDISDB = redis_parameters['DB']
    DBSUB = redis_parameters['DBSUB']
    REDISTTL = redis_parameters['TTL']

    wild_parameters =  wildlib.load_yaml(CONFIG, "Wildfire")
    WILDHOST = wild_parameters['HOST']
    WILDKEY = wild_parameters['KEY']
    OPTIMIZE_APICALL = wild_parameters['OPTIMIZE_CALL']
    STOP_AT_POSITIVE = wild_parameters['STOP_AT_POSITIVE']
    WILDTMPDIR = wild_parameters['TMPDIR']

    task_parameters = wildlib.load_yaml(CONFIG, "Multitask")
    TASK_TYPE = task_parameters['TYPE']
    QSIZE_SUBMIT = task_parameters['SIZE_SUBMIT']
    QSIZE_REDIS = task_parameters['SIZE_REDIS']

    ACCEPTED_MIME = wildlib.load_yaml(CONFIG,'AcceptedMIME')

else:
    sys.exit("Please check the config file! Config path: %s.\nHint: put a milter.conf in /etc/wildfire-milter/ folder." % CONFIG)
# =============================================================================

# check if all config parameters are present
for confvar in (
        SOCKET, UMASK, TIMEOUT, DEFER, MESSAGE, MAX_NESTED_ARCHIVE, MILTER_RETURN, REJECT_DETAIL,
        LOGFILE_DIR, LOGFILE_NAME, LOGSTDOUT,
        LOGHANDLER, SYSLOG_FAC, SYSLOG_LEVEL, SYSLOG_SOCKET, REDISHOST, REDISPORT, REDISAUTH, REDISDB, DBSUB, REDISTTL,
        WILDHOST, WILDKEY, OPTIMIZE_APICALL, WILDTMPDIR, TASK_TYPE, QSIZE_SUBMIT, QSIZE_REDIS, ACCEPTED_MIME):
    if confvar is None:
        sys.exit("Please check the config file! Some parameters are missing. This is an YAML syntax file!")

MILTER_RETURN = MILTER_RETURN.lower()
if MILTER_RETURN not in ('reject', 'discard', 'accept', 'defer'):
    sys.exit("Please check the config file! ON_VIRUS must be any of Reject, Discard, Defer or Accept!")
TASK_TYPE = TASK_TYPE.lower()
if TASK_TYPE not in ('thread', 'process', 'single'):
    sys.exit("Please check the config file! Multitask TYPE must be 'single', 'thread' or 'process' only")

if TASK_TYPE == 'process':
    from multiprocessing import Process as Thread, Queue
elif TASK_TYPE == 'thread':
    from threading import Thread
    from queue import Queue
elif TASK_TYPE == 'single':
    redisq = None
    submitq= None
if TASK_TYPE == 'process' or TASK_TYPE == 'thread':
    redisq = Queue(maxsize=QSIZE_REDIS)
    submitq= Queue(maxsize=QSIZE_SUBMIT)

Hash_Whitelist = None
WhiteList = None

if LOGHANDLER == 'file':
    LOGFILE_PATH = os.path.join(LOGFILE_DIR, LOGFILE_NAME)
    Path(LOGFILE_DIR).mkdir(exist_ok=True)
    Path(LOGFILE_PATH).touch()
else:
    LOGFILE_PATH = False

p = Path(WILDTMPDIR)
# The work dir should be created during the application setup really.
p.mkdir(exist_ok=True)

if not wildlib.set_log(LOGHANDLER, SYSLOG_SOCKET, SYSLOG_FAC, SYSLOG_LEVEL, LOGSTDOUT, LOGFILE_PATH):
    print("Something wrong in log definition")
    sys.exit(1)
log = logging.getLogger(wildlib.loggerName)


class WildfireMilter(Milter.Base):

    def __init__(self):  # A new instance with each new connection.
        self.flow = None
        self.scope = None
        self.IP = None
        self.port = None
        self.fromparms = None
        self.user = None
        self.canon_from = None
        self.IPname = None  # Name from a reverse IP lookup
        self.H = None
        self.fp = None
        self.R = []  # list of recipients
        self.nexthop = [] # list of nexthop
        self.queueid = None
        self.id = Milter.uniqueID()  # Integer incremented with each call.

    # each connection runs in its own thread and has its own WildfireMilter
    # instance.  Python code must be thread safe.
    @Milter.noreply
    def connect(self, IPname, family, hostaddr):
        global bg_redis_write, bg_submit_wf
        global TASK_TYPE, QSIZE_REDIS, QSIZE_SUBMIT
        print()
        # (self, 'ip068.subnet71.example.com', AF_INET, ('215.183.71.68', 4720) )
        # (self, 'ip6.mxout.example.com', AF_INET6,
        #   ('3ffe:80e8:d8::1', 4720, 1, 0) )
        if family == AF_INET6:
            self.flow = hostaddr[2]
            self.scope = hostaddr[3]
        else:
            pass
        self.fp =  None
        self.IP = hostaddr[0]
        self.port = hostaddr[1]
        self.IPname = IPname  # Name from a reverse IP lookup
        log = logging.getLogger(wildlib.loggerName)
        log.info('action=<connect> milter_id=<%d> orig_client_ip=<%s> orig_client=<%s> client_ip=<%s> client=<%s> server_ip=<%s> server=<%s>' %
                 (self.id, self.getsymval('{client_addr}'), self.getsymval('{client_name}'), self.IP, IPname,
                  self.getsymval('{daemon_addr}'), self.getsymval('{daemon_name}')))
        if TASK_TYPE != 'single':
            if not bg_redis_write.is_alive():
                log.critical('action=<redis_add> milter_id=<%d> error=<The %s to write into Redis is dead.Try to restart...>',
                             self.id, TASK_TYPE)
                redisq = Queue(maxsize=QSIZE_REDIS)
                bg_redis_write = Thread(target=redis_background_write, args=(redisq,))
                bg_redis_write.start()
            if not bg_submit_wf.is_alive():
                log.critical('action=<wildfire_submit> milter_id=<%d> error=<The %s to submit sample for Wildfire is dead. Try to restart...>',
                         self.id, TASK_TYPE)
                submitq = Queue(maxsize=QSIZE_SUBMIT)
                bg_submit_wf = Thread(target=submit_wildfire_background, args=(submitq,))
                bg_submit_wf.start()
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, mailfrom, *str):
        self.fromparms = Milter.param2dict(str)  # ESMTP parms
        self.user = self.getsymval('{auth_authen}')  # authenticated user
        self.canon_from = '@'.join(parse_addr(mailfrom))
        self.fp = BytesIO()
        self.fp.write(b"From %s %s\n" % (codecs.encode(self.canon_from, 'utf-8'), codecs.encode(time.ctime(), 'utf-8')))
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *str):
        toparms = Milter.param2dict(str)
        self.R.append(to)
        if self.getsymval('{rcpt_host}') not in self.nexthop and self.getsymval('{rcpt_host}') is not None:
            self.nexthop.append(self.getsymval('{rcpt_host}'))
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, hval):
        # add header to buffer
        self.fp.write(b"%s: %s\n" % (codecs.encode(name, 'utf-8'), codecs.encode(hval, 'utf-8')))
        return Milter.CONTINUE

    @Milter.noreply
    def eoh(self):
        self.queueid =  self.getsymval('i')
        self.fp.write(b"\n")  # terminate headers
        return Milter.CONTINUE

    @Milter.noreply
    def body(self, chunk):
        self.fp.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        all_verdicts = []
        if not self.fp:
            return Milter.ACCEPT  # no message collected - so no eom processing
        if not self.nexthop:
            self.nexthop = ['unavailable']
        log = logging.getLogger(wildlib.loggerName)
        try:
            self.fp.seek(0)
            msg = email.message_from_bytes(self.fp.getvalue())
            if self.fp:
                self.fp.close()
                self.fp = None
            if self.envelope_is_in_whitelist():
                self.addheader('X-WildMilter-Status', 'Whitelisted')
                return Milter.ACCEPT
            else:
                all_verdicts = self.checkforthreat(msg)
                msg = None
                return self.milter_result(all_verdicts)

        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            log.error("milter_id=<%d> queueid=<%s> action=<milter.accept> error=<Unexpected error - fall back to ACCEPT: %s %s %s>" % (
                self.id, self.queueid, exc_type, fname, exc_tb.tb_lineno))
            self.addheader('X-WildMilter-Status', 'Unchecked')
            return Milter.ACCEPT

    def close(self):
        # always called, even when abort is called.  Clean up
        # any external resources here.
        log = logging.getLogger(wildlib.loggerName)
        log.info("milter_id=<%d> client_ip=<%s> client=<%s> last_queueid=<%s> action=<close>", self.id, self.IP, self.IPname, self.queueid)
        if self.fp:
            self.fp.close()
            self.fp = None
        return Milter.CONTINUE

    def abort(self):
        # client disconnected prematurely
        log = logging.getLogger(wildlib.loggerName)
        log.debug("milter_id=<%d> client_ip=<%s> client=<%s> queueid=<%s> action=<abort>", self.id, self.IP, self.IPname, self.queueid)
        return Milter.CONTINUE

    ## === Support Functions ===
    def envelope_is_in_whitelist(self):
        """
          Lookup if the sender is at the whitelist
        """
        global WhiteList
        msg_from = self.canon_from
        msg_to = ','.join(self.R)

        # return if not RFC char detected
        if "\'" in msg_from:
            return False
        if "\'" in msg_to:
            return False

        log = logging.getLogger(wildlib.loggerName)
        if WhiteList is not None:
            # check if it is a list
            for name in WhiteList:
                if name not in (None, ''):
                    if any(name in s for s in msg_from):
                        log.info("milter_id=<%d> queue_id=<%s> action=<whitelist> from=<%s> result=<whitelisted> detail=<accept all attachments>" % (
                            self.id, self.queueid, msg_from))
                        return True
                    if any(name in s for s in msg_to):
                        log.info("milter_id=<%d> queue_id=<%s> action=<whitelist> to=<%s> result=<whitelisted> detail=<accept all attachments>" % (
                            self.id, self.queueid, msg_to))
                        return True
                    log.debug(
                        "milter_id=<%d> queue_id=<%s> action=<whitelist> from=<%s> to=<%s> result=<false> detail=<starting analysis of this mail>" % (
                            self.id, self.queueid, msg_from, msg_to))
        return False

    def checkforthreat(self, msg):
        """
            Check if attachments contain threats and it is whitelisted
        """
        global r
        global rsub
        global wfp
        all_files_to_inspect = []
        tmpdir = None
        tmpdirs = []
        log = logging.getLogger(wildlib.loggerName)
        logadd = ''
        verdicts = []
        try:
            count = 1
            for part in msg.walk():
                # for name, value in part.items():
                #     log.debug(' - %s: %r' % (name, value))
                content_type = part.get_content_type()
                if not content_type.startswith('multipart'):
                    filename = part.get_filename(None)
                    attachment = part.get_payload(decode=True)

                    if attachment is None or filename is None:
                    # The "or" is questionable. It could happen a text/plain part with no filename that magiclib
                    # considers as something other. Who is wrong?
                    # If I change to "and", then I must add:
                    # if filename is None
                    #   filename = 'noname'
                    # before 'attachment_fileobj.name = filename' to prevent exception in cleanup.
                        log.debug('milter_id=<%d> queue_id=<%s> action=<analyze> msg_part=<%d> content-type=<%r> filename=<%s> analyze=<False>' % (
                            self.id, self.queueid, count, content_type, filename))
                        continue
                    attachment_fileobj = BytesIO(attachment)
                    attachment_fileobj.name = filename

                    logadd = "milter_id=<%d> queue_id=<%s> msg_part=<%d> content-type=<%s> filename=<%s> " % (
                            self.id, self.queueid, count, content_type, filename)

                    # We check if the attachment has to be analyzed.
                    # Some archives such as 7zip are currently accepted for verdict. Other archives are deflated in a
                    # temp dir and then passed to check_verdict.
                    files_to_inspect, tmpdir = wildlib.archiveWalk(fileobj=attachment_fileobj, MAXNESTED=MAX_NESTED_ARCHIVE,
                                                           outdirectory=WILDTMPDIR, ACCEPTEDMIME=ACCEPTED_MIME, prefixlog=logadd)
                    if tmpdir is not None:
                        tmpdirs.append(tmpdir)
                    if OPTIMIZE_APICALL:
                        all_files_to_inspect = all_files_to_inspect + files_to_inspect
                    else:
                        for anyfile in files_to_inspect:
                            verdict =wildlib.check_verdict(r, rsub, REDISTTL, wfp, anyfile, WILDTMPDIR, Hash_Whitelist, redisq, submitq, logadd)
                            if verdict:
                                verdicts.append({'name': os.path.basename(anyfile.name), 'verdict': verdict})
                            if STOP_AT_POSITIVE and verdict > 0:
                                break
                        wildlib.cleanup(files_to_inspect, tmpdirs, logadd)
                        tmpdirs = []
                        files_to_inspect = []
                else:
                    log.debug('milter_id=<%d> queue_id=<%s> action=<analyze> msg_part=<%d> content-type=<%r> analyze=<False>' % (
                        self.id, self.queueid, count, content_type))
                count += 1
            # End of all parts
            if OPTIMIZE_APICALL:
                logadd = "milter_id=<%d> queue_id=<%s> " % (self.id, self.queueid)
                verdicts = wildlib.check_verdicts(r, rsub, REDISTTL, wfp, all_files_to_inspect, WILDTMPDIR,
                    STOP_AT_POSITIVE, Hash_Whitelist, redisq, submitq, logadd)
                wildlib.cleanup(all_files_to_inspect, tmpdirs, logadd)
                tmpdirs = []
                files_to_inspect = []

        except Exception:
            wildlib.trackException(action='the message', prefixlog=('milter_id=<%d> queue_id=<%s> action=<analyze> ',
                                                                    self.id, self.queueid))
            if OPTIMIZE_APICALL:
                wildlib.cleanup(all_files_to_inspect, tmpdirs, logadd)
        return verdicts

    def milter_result(self, dict_verdicts):
        log = logging.getLogger(wildlib.loggerName)
        verdict_name = {1: 'Malware',
                        2: 'Grayware',
                        4: 'Phishing',
                        -100: 'Pending analysis for suspicious content',
                        -102: 'Suspicious content submitted for analysis'
                        }
        is_threat = False
        is_pending = False
        th_message = ''
        pending_message = ''
        th_list = []
        susp_list = []
        if not dict_verdicts:
            # Clean Message
            self.addheader('X-WildMilter-Status', 'Clean')
            try:
                log.info('milter_id=<%d> queue_id=<%s> status=<clean> action=<%s> nexthop=<%s>',
                     self.id, self.queueid, 'milter.accept', ','.join(self.nexthop))
            except:
                wildlib.trackException('log','')
            return Milter.ACCEPT

        # Determine the class (threat or pending)
        for dict_verdict in dict_verdicts:
            if dict_verdict['verdict'] > 0:
                th_type = verdict_name.get(dict_verdict['verdict'], 'unknown')
                th_list.append({'name': dict_verdict['name'], 'type': th_type})
                th_message = th_message + ' %s in %s.' % (th_type, dict_verdict['name'])
                if not is_threat:
                    is_threat = True
                is_pending = False
            if dict_verdict['verdict'] < 0:
                pending_message = verdict_name.get(dict_verdict['verdict'], verdict_name[-100])
                susp_list.append(dict_verdict['name'])
                if not is_threat:
                    is_pending = True
        if is_pending:
            pending_message += '. Please wait few minutes before resend'

        # Return by class and options
        if is_threat:
            if MILTER_RETURN == 'reject' or MILTER_RETURN == 'discard':
                if REJECT_DETAIL:
                    # Set Reject Message - definition from here
                    # https://www.iana.org/assignments/smtp-enhanced-status-codes/smtp-enhanced-status-codes.xhtml
                    self.setreply('550', '5.7.1', '{}: {}'.format(MESSAGE, th_message))
                else:
                    self.setreply('550', '5.7.1', MESSAGE)
                log.warning('milter_id=<%d> queue_id=<%s> status=<threat> action=<%s>' %
                            (self.id, self.queueid, 'milter.' + MILTER_RETURN))
                if MILTER_RETURN == 'reject':
                    return Milter.REJECT
                else:
                    return Milter.DISCARD
            if MILTER_RETURN == 'defer':
                # Defer forever and ever
                if REJECT_DETAIL:
                    self.setreply('454', '4.7.0', '{}: {}'.format(MESSAGE, th_message))
                else:
                    self.setreply('454', '4.7.0', MESSAGE)
                log.warning('milter_id=<%d> queue_id=<%s> status=<threat> action=<%s>' %
                            (self.id, self.queueid, 'milter.defer'))
                return Milter.TEMPFAIL
            if MILTER_RETURN == 'accept':
                for th in th_list:
                    self.addheader('X-WildMilter-Threats', '"%s" type="%s";' % (th['name'], th['type']))
                self.addheader('X-WildMilter-Status', 'Infected')
                log.warning('milter_id=<%d> queue_id=<%s> status=<threat> action=<%s> nexthop=<%s>',
                    self.id, self.queueid, 'milter.accept', ','.join(self.nexthop))
                return Milter.ACCEPT
        elif is_pending:
            if (MILTER_RETURN == 'reject' or MILTER_RETURN == 'defer' or MILTER_RETURN == 'discard') and DEFER:
                self.setreply('454', '4.7.0', pending_message)
                log.warning('milter_id=<%d> queue_id=<%s> status=<suspicious> action=<%s>' %
                    (self.id, self.queueid, 'milter.defer'))
                return Milter.TEMPFAIL
            else:
                self.addheader('X-WildMilter-Status', 'Suspicious')
                for sp in susp_list:
                    self.addheader('X-WildMilter-Threats', "name=<%s>" % sp)
                log.warning('milter_id=<%d> queue_id=<%s> status=<suspicious> action=<%s> nexthop=<%s>',
                    self.id, self.queueid, 'milter.accept', ','.join(self.nexthop))
                return Milter.ACCEPT
        else:
            # Clean Message
            self.addheader('X-WildMilter-Status', 'Clean')
            log.debug('milter_id=<%d> queue_id=<%s> status=<clean> action=<%s> nexthop=<%s>',
                      self.id, self.queueid, 'milter.accept', ','.join(self.nexthop))
            return Milter.ACCEPT


def redis_background_write(q):
    """ Add key and value to main Redis Cache """
    if TASK_TYPE == 'process':
        """Ignore SIGINT in child workers."""
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    redis_obj = wildlib.redisConnect(REDISHOST, REDISPORT, REDISDB, REDISAUTH)
    while True:
        args = q.get()
        if args is None:
            break
        # Perform the action
        key, value, redis_ttl, prefixlog = args
        wildlib.add_to_redis(redis_obj, key, value, redis_ttl, prefixlog)

def submit_wildfire_background(q):
    """ Submit an attachment to Wildfire for further analysis """
    if TASK_TYPE == 'process':
        """Ignore SIGINT in child workers."""
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    redis_obj = wildlib.redisConnect(REDISHOST, REDISPORT, DBSUB, REDISAUTH)
    wfpsubmit = wildlib.wildfireConnect(WILDHOST, WILDKEY)
    while True:
        args = q.get()
        if args is None:
            break
        # Perform the action
        redis_ttl, key, attach, tmp_dir, prefixl = args
        wildlib.submit_verdict_to_wildfire(wfpsubmit, redis_obj, redis_ttl, key, attach, spool_path=tmp_dir, prefixlog=prefixl)

# ===


def main():
    if LOGHANDLER == 'file':
        endstr = '**'
        # make sure the log directory exists:
        try:
            os.makedirs(LOGFILE_DIR, 0o0027)
        except:
            pass
    else:
        endstr = ''

    # Load the whitelist into memory
    global WhiteList, Hash_Whitelist
    global r
    global rsub
    global wfp
    global bg_redis_write
    global bg_submit_wf

    WhiteList, Hash_Whitelist= wildlib.whiteListLoad(CONFIG)

    # Register to have the Milter factory create instances of your class:
    Milter.factory = WildfireMilter
    flags = Milter.ADDHDRS
    Milter.set_flags(flags)  # tell Sendmail which features we use
    print("\n*************************************************************")
    print("*********** %s startup - Version %s ***********" % ('Wildfire Milter', __version__))
    print('*************  logging to %s' % LOGHANDLER, end='')
    if LOGSTDOUT:
        print(' and to stdout ', end=endstr)
    else:
        print(' **************', end=endstr)
    print("**************\n*************************************************************\n")
    log.info('* Starting %s v%s - listening on %s' % ('Wildfire Milter', __version__, SOCKET))
    log.debug('* Python version: %s' % str(sys.version).replace('\n', ' - '))
    log.debug('* Config file: %s' % CONFIG)
    print()
    sys.stdout.flush()

    # Initialize Wildfire API
    wfp = wildlib.wildfireConnect(WILDHOST, WILDKEY)

    # Initialize main Redis Cache
    r = wildlib.redisConnect(REDISHOST, REDISPORT, REDISDB, REDISAUTH)
    # Initialize Redis Cache for Wildfire submit
    if  'threading' in  sys.modules and submitq is not None:
        # This is done in another process/thread
        rsub = None
    else:
        rsub = wildlib.redisConnect(REDISHOST, REDISPORT, DBSUB, REDISAUTH)

    # ensure desired permissions on unix socket
    os.umask(UMASK)

    # set the "last" fall back to ACCEPT if exception occur
    Milter.set_exception_policy(Milter.ACCEPT)

    if TASK_TYPE != 'single':
        bg_redis_write = Thread(target=redis_background_write, args=(redisq,))
        bg_submit_wf   = Thread(target=submit_wildfire_background, args=(submitq,))
        bg_redis_write.start()
        bg_submit_wf.start()
    # start the milter
    Milter.runmilter('WildfireMilter', SOCKET, TIMEOUT)
    if TASK_TYPE != 'single':
        # Terminate the running threads.
        redisq.put(None)
        submitq.put(None)
        bg_redis_write.join()
        bg_submit_wf.join()

    log.info('Wildfire Milter shutdown')
    print("\n*********** %s shutdown ***********\n" % 'WildfireMilter')


if __name__ == "__main__":
    main()
