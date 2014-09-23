# coding: utf-8
# * Authors:
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
#       * TJEBBES Gaston <g.t@majerti.fr>
#

"""
Salt module for samba stats

Sends out structured data about

- users (IP clients) of samba shares
- locks in these shares
- disk usage for the corresponding mountpoints
"""

__author__ = "Feth Arezki, Julien Miotte, Gaston Tjebbes"
__copyright__ = "Copyright 2014, Majerti"
__credits__ = ["Feth Arezki", "Julien Miotte", "Gaston Tjebbes"]
__license__ = "GPLv3"
__version__ = "0.1"
__maintainer__ = "Feth Arezki"
__email__ = "contact hATh majerti.fr"


import collections
import datetime
import os
import re
import tempfile
import shutil
import sys


__salt__ = None  # overridden at runtime


class SmbstatusError(Exception):
    """
    Exception raised when smbstatus returns with non 0 status.
    """
    pass

_SMBSTATUS = '/usr/bin/smbstatus'
_SMBSTATUS_COMMAND = '{executable} --{command} -d 0 > {tempfile}'


def _smbstatus_cmd(command, test=False):
    if not test:
        tempdir = tempfile.mkdtemp()
        tempfname = os.path.join(tempdir, "smbstatus.{0}".format(command))
        rundata = __salt__['cmd.run_all'](_SMBSTATUS_COMMAND.format(
            executable=_SMBSTATUS,
            command=command,
            tempfile=tempfname,
            ),
            env={'LC_ALL': 'en_US.UTF-8'},
            )
    else:
        tempfname = os.path.join(
            os.path.dirname(sys.argv[0]),
            'sample.smbstatus.{0}'.format(command)
            )
        rundata = {'retcode': 0}

    if rundata['retcode'] != 0:
        if not test:
            shutil.rmtree(tempdir)
        raise SmbstatusError(rundata['stderr'])

    rundata['stdout'] = stdout = []
    with open(tempfname, 'rb') as output:
        for line in output:
            try:
                guessed_output = line.decode("utf-8")
            except UnicodeDecodeError:
                guessed_output = line.decode("latin-1")
            stdout.append(guessed_output)

    if not test:
        shutil.rmtree(tempdir)

    return rundata


def __virtualname__():
    """
    This module's name
    """
    if not os.path.exists(_SMBSTATUS):
        return False
    return 'samba_usage'


def _share_item_skel():
    return {'machines': [], 'locked_files': []}


def _avail_space():
    samba_dirs = __salt__['pillar.get']('samba_dirs', ('/mnt/samba',))

    directory_to_mount_point = {}
    for directory in samba_dirs:
        stat_data = __salt__['cmd.run_all']("stat -c '%m' {0}".format(directory))
        if stat_data['retcode'] != 0:
            raise SmbstatusError(stat_data['stderr'])

        directory_to_mount_point[directory] = stat_data['stdout'].strip()

    space_data = __salt__['disk.usage']()

    single_mount_points = set(directory_to_mount_point.values())

    space_info = {}
    for mount_point in single_mount_points:
        single_info = space_data[mount_point]
        space_info[mount_point] ={
                'used': single_info['used'],
                'available': single_info['available'],
                'total': single_info['1K-blocks'],
            }

    return {
        'mount_points': directory_to_mount_point,
        'disk_usage': space_info,
    }



def stats(test=False):
    """
    public function: returns stats about samba shares
    """
    used_shares_gen = _smbstatus_data('shares', _parse_share_line, test=test)
    locked_files_gen = _smbstatus_data('locks', _parse_lock_line, test=test)

    used_shares = collections.defaultdict(_share_item_skel)

    try:
        for share, item in used_shares_gen:
            used_shares[share]['machines'].append(item)

        for share, item in locked_files_gen:
            used_shares[share]['locked_files'].append(item)

        avail_space = _avail_space()
    except SmbstatusError:
        return {'in_error': True}

    return {
        'in_error': False,
        'status': used_shares,
        'avail_space': avail_space,
        }


def _smbstatus_data(command, line_parser, test=False):
    """
    Generator of data dicts for every line of smbstatus --shares or --locks

    :param str status: standard output of the smbstatus command
    :param function parser: parser callbak for every line
    """
    rundata = _smbstatus_cmd(command, test=test)

    for index, line in enumerate(rundata['stdout']):
        value = line_parser(index, line)
        if value is None:
            continue

        if 'date' in value:
            # isoformat!
            assert len(value['date']) == 19, \
                u"len is {0}\n<<{1}>> in line {2}\n{3}".format(
                    len(value['date']),
                    value['date'],
                    index,
                    line,
                )

        share = value.pop('share')
        yield share, value


_STATUS_IGNORED_STARTS = (
    'Ignoring unknown parameter',
    'Unknown parameter encountered',
    'Processing section',
    'rlimit_max',
    '----------------',
)


_LOCKS_IGNORED_STARTS = (
    'Locked files:',
    '----------------',
    'Pid',
    'No locked files',
)


_DAYSOFWEEK = ur"(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
_MONTHOFYEAR = ur"(?P<moy>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_DAYOFMONTH = ur"(?P<dom>" \
    + '|'.join('%2d' % value for value in xrange(32)) \
    + ")"
_TIMEOFDAY = ur"(?P<tod>\d\d:\d\d:\d\d)"
_YEAR = ur"(?P<year>20\d\d)" #  bug in 2100

_DATE = " ".join((
    _DAYSOFWEEK,
    _MONTHOFYEAR,
    _DAYOFMONTH,
    _TIMEOFDAY,
    _YEAR
    ))

# from https://forge.univention.org/svn/dev/branches/ucs-3.0/ucs-school/ucs-school-lib/python/smbstatus.py # NOQA
# this is AGPLv3
# Copyright 2012 Univention GmbH
_REGEX_LOCKED_FILES = re.compile(
    ur'(?P<pid>[0-9]+)\t+'
    ur'(?P<uid>[0-9]+)\t+'
    ur'(?P<denyMode>[A-Z_]+)\s+'
    ur'(?P<access>[0-9xabcdef]+)\t+'
    ur'(?P<rw>[A-Z]+)\t+'
    ur'(?P<oplock>[A-Z_+]+)\t+'
    ur'(?P<sharePath>[^\t]+)\t+'
    ur'(?P<filename>.+)\t+'
    + _DATE,
    flags=re.UNICODE,
    )


def _normdate(datestr):
    return datetime.datetime.strptime(
        datestr,
        '%a %b %d %H:%M:%S %Y'
    ).isoformat()

def _parse_lock_line(index, line):
    if not line or line == '\n':
        print "empty line: %d (zero indexed)" % index
        return None
    if any(line.startswith(ignored) for ignored in _LOCKS_IGNORED_STARTS):
        return None

    # replace multi spaces by tabs
    fixed_line = re.sub(u'  +', u'\t', line, flags=re.UNICODE)
    parsed = _REGEX_LOCKED_FILES.match(fixed_line)

    if parsed is None:
        print("unparseable line (zero indexed:%d) : " % index, line)
        return None

    result = parsed.groupdict()

    date = _normdate('{dow} {moy} {dom} {tod} {year}'.format(**result))
    for key in ('dow', 'moy', 'dom', 'tod', 'year'):
        result.pop(key)
    result['date'] = date

    result['share'] = os.path.basename(result.pop('sharePath'))
    return result


def _parse_share_line(index, line):
    """
    build a data dict from a line from the command output

    If unrelevant, returns None
    """
    if any(line.startswith(ignored) for ignored in _STATUS_IGNORED_STARTS):
        return None

    split_line = line.split()

    if not split_line:
        return
    if split_line == ['Service', 'pid', 'machine', 'Connected', 'at']:
        return None

    return {
        'share': split_line[0],
        #  pid = pos 1
        'machine': split_line[2],
        'date': _normdate(' '.join(split_line[3:])),
        }

if __name__ == "__main__":
    stats(test=True)
