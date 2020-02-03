#!/usr/bin/env python3

import hashlib
import logging
import logging.handlers
import os
from shlex import quote
import shutil
import sys
import tempfile
import traceback

import magic
import pan.wfapi
import patoolib
import redis
import yaml
from patoolib import util

loggerName = 'wildfire'

def set_log(handler_type, socket, facility, level='INFO', stdout=False, filepath=False):
    log = logging.getLogger(loggerName)
    log.setLevel(level)
    formatter_syslog = logging.Formatter('%(module)s[%(process)d]: %(message)s')
    formatter_stdout = logging.Formatter('%(module)-16s[%(process)d]/%(funcName)-15s: %(levelname)8s: %(message)s')
    formatter_file   = logging.Formatter('%(asctime)s %(module)s[%(process)d]/%(funcName)s: %(levelname)8s: %(message)s')

    if handler_type == 'syslog':
        handler_syslog = logging.handlers.SysLogHandler(address=socket, facility=facility)
        handler_syslog.setFormatter(formatter_syslog)
        handler_syslog.setLevel(level)
        log.addHandler(handler_syslog)
    if handler_type == 'file':
        if not filepath:
            return False
        oldumask = os.umask(0o0026)
        handler_file = logging.handlers.WatchedFileHandler(filepath, encoding='utf8')
        handler_file.setFormatter(formatter_file)
        handler_file.setLevel(level)
        log.addHandler(handler_file)
        os.umask(oldumask)
    if stdout:
        handler_out = logging.StreamHandler(sys.stdout)
        handler_out.setLevel(level)
        handler_out.setFormatter(formatter_stdout)
        log.addHandler(handler_out)
    return True


def trackException(action, prefixlog=''):
    log = logging.getLogger(loggerName)
    log.error('%serror=<Error while processing %s>' % (prefixlog, action))
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    exep = ''.join(line for line in lines)
    log.exception("%sException code: <%s>" % (prefixlog, exep.replace('\n', ' - ')))


def hash_in_whitelist(Hash_Whitelist, wildhash, prefixlog=''):
    """
      Lookup for hash in whitelist
    """
    log = logging.getLogger(loggerName)

    if Hash_Whitelist is not None:
       for hash in Hash_Whitelist:
         if hash not in (None, ''):
             if hash == wildhash:
                log.info("%s action=<whitelist> key=<%s> result=<True> detail=<accepting attachment>",
                            prefixlog, hash)
                return True
    return False


class TooManyArchivesException(Exception):
    """ Custom exception class for archive bomb exception """
    pass


def is_archive(filename):
    """Detect if the file is a known Patool archive."""
    mime, compression = util.guess_mime(filename)
    if mime in util.ArchiveMimetypes:
        return True
    return False


def archiveWalk(fileobj=None, MAXNESTED=0, count=0, outdirectory='/tmp', listfile=None, ACCEPTEDMIME=[], prefixlog=''):
    """
        Walk in archive file and extract all possible files.
        The fileobj is written in a own tempdir inside outdirectory.
        If the written fileobj is a known archive is then deflated in a contentdir inside
        the tempdir. The process is recursive for each archive file found.

        Return a list of full temp path file to be analyzed and the path which contains
        all files.
    """
    if listfile is None:
        listfile = []
    if count == 0:
        listfile = []
    if fileobj is None:
        return listfile
    rootDir = None
    log = logging.getLogger(loggerName)
    fcontent = fileobj.read()
    magicType = magic.from_buffer(fcontent, mime=True)
    if to_be_analyzed(fileobj, magicType, ACCEPTEDMIME, prefixlog):
        listfile.append(fileobj)
    else:
        # create a random secure temp file
        if count == 0:
            fname = fileobj.name
            if fname is None:
                fname = 'noname'
            extn = (os.path.splitext(fname)[1]).lower()
            # where to create the archive attachment
            tempdir = tempfile.mkdtemp(prefix=extn, dir=outdirectory)
            rootDir = tempdir
            # create the archive
            tmp_fs, tmpfpath = tempfile.mkstemp(suffix=extn, dir=tempdir)
            tmpfile = os.fdopen(tmp_fs, "wb")
            tmpfile.write(fcontent)
            # Close the file to avoid the open file exception
            tmpfile.close()
            fileobj.close()
            fcontent = None
            log.debug('%saction=<free mem> result=<True> name=<%s>',prefixlog,fname)
        else:
            tmpfpath = fileobj.name
        if is_archive(tmpfpath):
            # where to deflate the archive
            if count > 0:
                tempdir = os.path.split(tmpfpath)[0]
            try:
                # Check if we walk into too many nested archives
                if count >= MAXNESTED:
                    shutil.rmtree(tempdir)
                    raise TooManyArchivesException(
                        "%s action=<deflate> error=<Too many nested zips found - possible zipbomb!>" % prefixlog)
                # Otherwise proceed to deflate
                contentdir = tempfile.mkdtemp(prefix='content_', dir=tempdir)
                patoolib.extract_archive(tmpfpath, outdir=contentdir, verbosity=-1, interactive=False)
                # List all file in archive
                ## r=root, d=directories, f = files
                for r, d, f in os.walk(contentdir):
                    for file in f:
                        file_with_path = os.path.join(r, file)
                        fpath, fname = os.path.split(file_with_path)
                        fo = open(file_with_path, 'rb')
                        archiveWalk(fo, MAXNESTED, count + 1, contentdir + '/' + fpath, listfile, ACCEPTEDMIME, prefixlog)
            except patoolib.util.PatoolError as err:
                log.error('%sfilename=<%s> action=<deflate> error=<%s>',
                          prefixlog, fileobj.name, str(err).replace('>','"').replace('<','"'))
            except Exception:
                trackException('the archive ' + fileobj.name, prefixlog)
        if fileobj.name is not None:
            name_to_log = os.path.basename(tmpfpath)
        else:
            name_to_log = None
        fileobj.close()
        log.debug('%saction=<free mem> result=<True> name=<%s>', prefixlog, name_to_log)
    return listfile, rootDir


def cleanup(filelist=None, temp_path=[], prefixlog=''):
    """
    Clean the temp path created by ArchiveWalk
    """
    if filelist is None:
        filelist = []
    log = logging.getLogger(loggerName)
    for fname in filelist:
        try:
            fname.close()
            log.debug('%saction=<free mem> result=<True> name=<%s>' % (prefixlog, fname.name))
        except:
            trackException('<free mem>', prefixlog)
    for tempdir in temp_path:
        try:
            shutil.rmtree(quote(tempdir))
            log.debug('%saction=<delete> result=<True> path=<%s>', prefixlog, tempdir)
        except:
            trackException('cleanup tmpdir', prefixlog)
            return False
    return True


def to_be_analyzed(fileobj, mtype, accepted_mime, prefixlog=''):
    """
    return True if mtype is in accepted_mime types and of suitable size
    accepted_mime is a list of dictionary, such as:
        accepted_mime = [
          {'type': 'application/x-dosexec', 'size': 10},
          {'type': 'application/msword', 'size': 2},
          {'type': 'application/java-archive', 'size': 5}
        ]
    """
    result = False
    log = logging.getLogger(loggerName)
    data = fileobj.read()

    size = sys.getsizeof(data)
    for this in accepted_mime:
        if mtype in this['type']:
            if size < this['size'] * 1048576:
                result = True
                break
    if fileobj.name is not None:
        name_to_log = os.path.basename(fileobj.name)
    else:
        name_to_log = None
    eventlog = '%s action=<analyze> name=<%s> detected_type=<%s> size=<%d> analyze=<%r>'
    if result:
        log.info(eventlog, prefixlog, name_to_log, mtype, size, result)
    else:
        log.debug(eventlog, prefixlog, name_to_log, mtype, size, result)
    return result


def submit_verdict_to_wildfire(wildapi, redis, redis_ttl, digest, attachment, spool_path='/run/wildfire', prefixlog=''):
    log = logging.getLogger(loggerName)
    thisvalue = None
    # Ask to Redis to find out already submitted attachments
    thisvalue = redis.get(digest)
    size = sys.getsizeof(attachment)
    if thisvalue is not None:
        log.debug('%saction=<wildfire_submit> result=<already> detail=<part already submitted> size=<%d>',
                  prefixlog, size)
        return True
    #
    # Submit to Wildfire
    # Don't return inside the context if you want temp file to be closed?
    with tempfile.NamedTemporaryFile(dir=spool_path) as fp:
        fp.write(attachment)
        try:
            wildapi.submit(fp.name)
            log.info(
                '%saction=<wildfire_submit> result=<success> size=<%d> detail=<part submitted for further analysis>',
                prefixlog, size)
            return_as = True
            add_to_redis(redis, digest, 1, redis_ttl, prefixlog)
        except pan.wfapi.PanWFapiError as msg:
            log.error('%saction=<wildfire_submit> result=<fail> size=<%d> error=<%s>', prefixlog, size, msg)
            return_as = False
    return return_as


def add_to_redis(redis, key, value, redis_ttl, prefixlog):
    result = False
    log = logging.getLogger(loggerName)
    try:
        ## Add to Redis
        result = redis.set(key, value, ex=redis_ttl, nx=True, xx=False)
        if result is True:
            log.info("%saction=<redis_add> key=<%s> value=<%s> result=<success>" % (prefixlog, key, value))
        if result is False:
            log.error("%saction=<redis_add> key=<%s> value=<%s> result=<fail>" % (prefixlog, key, value))
        if result is None:
            log.error("%saction=<redis_add> key=<%s> value=<%s> result=<fail> detail=<already exist>" % (
            prefixlog, key, value))
    except redis.RedisError as err:
        log.error('%saction=<redis_add> key=<%s> value=<%s> error=<%s>' % (prefixlog, key, value, err))
    return result


def check_verdicts(redis, redis_sub, redis_ttl, wildapi, attachments_obj, tmp_dir='/run/wildfire', stop=False, wl_hash=[],
                   redis_queue=None, wf_queue=None, prefixlog=''):
    log = logging.getLogger(loggerName)
    listvalue = []
    wildattachs = {}
    ## Hash
    for attachment_obj in attachments_obj:
        attachment_obj.seek(0)
        attachment = attachment_obj.read()
        attachment_name = os.path.basename(attachment_obj.name)
        thishash = hashlib.sha256(attachment).hexdigest()
        if  hash_in_whitelist(wl_hash, thishash, prefixlog):
            continue
        ## Try to read in Redis
        thisvalue = redis.get(thishash)
        if thisvalue is not None:
            thisvalue = thisvalue.decode('utf-8')
            listvalue.append({'name': attachment_name, 'verdict': int(thisvalue)})
            if stop and int(thisvalue) > 0:
                return listvalue
        else:
            # We have to ask to Wildfire
            wildattachs[thishash] = {'content': attachment, 'name': attachment_name}
        log.info("%saction=<redis_get> name=<%s> key=<%s> value=<%s>" % (
            prefixlog, attachment_name, thishash, thisvalue))
    ## If not in Redis, read from Wildfire
    if wildattachs:
        try:
            hashes = wildattachs.keys()
            wildapi.verdicts(hashes)
        except pan.wfapi.PanWFapiError as msg:
            result = wildapi.http_code
            reason = wildapi.http_reason
            log.critical(
                '%saction=<wildfire_multiget> result=<fail> detail=<%s> result_code=<%d> error=<%s>' % (
                prefixlog, msg, result, reason))
            return False
        if wildapi.xml_element_root is None:
            log.warning("%saction=<wildfire_multiget> result=<fail> error=<empty API response>" % prefixlog)
            return False
        elem = wildapi.xml_element_root
        nelem = len(wildapi.xml_element_root.getchildren())
        if nelem != len(hashes):
            log.error("%saction=<wildfire_multiget> result=<fail> error=<malformed API response>" % prefixlog)
            return False
        for item in elem:
            thishash = None
            thisvalue = None
            for verdict in item:
                if verdict.tag == 'sha256':
                    thishash = verdict.text
                    if thishash not in hashes:
                        log.error(
                            "%saction=<wildfire_multiget> key=<%s> result=<fail> error=<inconsistent API response>" % (
                            prefixlog, thishash))
                        return False
                if verdict.tag == 'verdict':
                    thisvalue = int(verdict.text)
                    log.info("%saction=<wildfire_multiget> name=<%s> key=<%s> value=<%s> result=<success>" % (
                    prefixlog, wildattachs[thishash]['name'], thishash, thisvalue))
                    if thisvalue == -102:
                        ### Submit to wildfire
                        attach = wildattachs[thishash]['content']
                        if  'threading' in  sys.modules and wf_queue is not None:
                            args = (redis_ttl, thishash, attach, tmp_dir, prefixlog + 'name=<%s> ' % wildattachs[thishash]['name'])
                            wf_queue.put(args)
                        else:
                            submit_verdict_to_wildfire(wildapi, redis_sub, redis_ttl, thishash, attach, spool_path=tmp_dir,
                                     prefixlog=prefixlog + 'name=<%s> ' % wildattachs[thishash]['name'])
                    elif thisvalue >= 0:
                        # If multiprocessing, the threading is loaded too
                        if  'threading' in  sys.modules and redis_queue is not None:
                            args = (thishash, thisvalue, redis_ttl, prefixlog + 'name=<%s> ' % wildattachs[thishash]['name'])
                            redis_queue.put(args)
                        else:
                            add_to_redis(redis, thishash, thisvalue, redis_ttl, prefixlog + 'name=<%s> ' % wildattachs[thishash]['name'])
                    listvalue.append({'name': wildattachs[thishash]['name'], 'verdict': thisvalue})
                    if stop and thisvalue > 0:
                        return listvalue
    return listvalue


def check_verdict(redis, redis_sub, redis_ttl, wildapi, attachment_obj, tmp_dir='/run/wildfire', wl_hash=[],
                  redis_queue=None, wf_queue=None, prefixlog=''):
    log = logging.getLogger(loggerName)
    attachment_obj.seek(0)
    attachment = attachment_obj.read()
    fname = os.path.basename(attachment_obj.name)
    ## Hash
    hash = hashlib.sha256(attachment).hexdigest()
    if  hash_in_whitelist(wl_hash, hash, prefixlog):
            return False
    ## Try to read in Redis
    kvalue = redis.get(hash)
    if kvalue is not None:
        kvalue = kvalue.decode('utf-8')
    log.info("%saction=<redis_get> name=<%s> key=<%s> value=<%s>" % (prefixlog, fname, hash, kvalue))
    if kvalue is not None:
        return int(kvalue)
    ## If not in Redis, read from Wildfire
    try:
        wildapi.verdict(hash)
    except pan.wfapi.PanWFapiError as msg:
        result = wildapi.http_code
        reason = wildapi.http_reason
        log.critical(
            '%saction=<wildfire_get> name=<%s> key=<%s> value=<%s> result=<fail> detail=<%s> result_code=<%d> error=<%s>' % (
            prefixlog, fname, hash, kvalue, msg, result, reason))
        return False

    if wildapi.xml_element_root is None:
        log.warning(
            "%saction=<wildfire_get> name=<%s> key=<%s> value=<%s> result=<fail> error=<empty API response>" % (
            prefixlog, fname, hash, kvalue))
        return False
    elem = wildapi.xml_element_root
    nelem = len(wildapi.xml_element_root.getchildren())
    if nelem != 1:
        log.error(
            "%saction=<wildfire_get> name=<%s> key=<%s> value=<%s> result=<fail> error=<malformed API response>" % (
            prefixlog, fname, hash, kvalue))
        return False

    kvalue = False
    for verdict in elem[0]:
        if verdict.tag == 'sha256':
            if verdict.text != hash:
                log.error(
                    "%saction=<wildfire_get> name=<%s> key=<%s> value=<%s> result=<fail> error=<inconsistent API response>" % (
                    prefixlog, fname, hash, kvalue))
                return False
        if verdict.tag == 'verdict':
            kvalue = int(verdict.text)
            log.info("%saction=<wildfire_get> name=<%s> key=<%s> value=<%s> result=<success>" % (
                prefixlog, fname, hash, kvalue))
            if kvalue == -102:
                ## Submit to wildfire
                if  'threading' in  sys.modules and wf_queue is not None:
                    args = (redis_ttl, hash, attachment, tmp_dir, prefixlog + 'name=<%s> ' % fname)
                    wf_queue.put(args)
                else:
                    submit_verdict_to_wildfire(wildapi, redis_sub, redis_ttl, hash, attachment, spool_path=tmp_dir,
                                               prefixlog=prefixlog + 'name=<%s> ' % fname)
            elif kvalue >= 0:
                    # If multiprocessing, the threading is loaded too
                    if  'threading' in  sys.modules and redis_queue is not None:
                        args = (hash, kvalue, redis_ttl, prefixlog + 'name=<%s> ' % fname)
                        redis_queue.put(args)
                    else:
                        add_to_redis(redis, hash, kvalue, redis_ttl, prefixlog + 'name=<%s> ' % fname)
    return kvalue


def load_yaml(file, part):
    """
            Load the YAML configuration file.
    """
    with open(file, 'r') as ymlfile:
        config_parameters = yaml.load(ymlfile, Loader=yaml.SafeLoader)[part]
    return config_parameters


def whiteListLoad(CONFIG):
    """
            Function to load the data from the WhiteList file and load into memory
    """
    whitelist_parameters =  load_yaml(CONFIG, "Whitelist")
    return whitelist_parameters["Envelopes"], whitelist_parameters["Hash"]


def wildfireConnect(apihost, apikey):
    log = logging.getLogger(loggerName)
    try:
        wfapi = pan.wfapi.PanWFapi(
            tag='wildfire',
            api_key=apikey,
            hostname=apihost
        )
        log.info('action=<wfapi_init> server=<%s> result=<success>' % apihost)
    except pan.wfapi.PanWFapiError as msg:
        log.critical('action=<wfapi_init> server=<%s> result=<fail> error=<%s>' % (apihost, msg))
        sys.exit(1)

    return wfapi


def redisConnect(redishost, redisport, redisdb, redisauth):
    log = logging.getLogger(loggerName)
    try:
        r = redis.StrictRedis(host=redishost, port=redisport, db=redisdb, password=redisauth)
        r.ping()
        log.info('action=<redis_init> server=<%s> port=<%d> db=<%d> result=<success>' % (redishost, redisport, redisdb))
    except (redis.ConnectionError, redis.ResponseError) as e:
        log.critical('action=<redis_init> server=<%s> port=<%d> db=<%d> result=<fail> error=<%s>' % (
            redishost, redisport, redisdb, repr(e)))
        sys.exit(1)
    return r


class TooManyZipException(Exception):
    pass


