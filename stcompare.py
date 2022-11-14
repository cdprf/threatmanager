#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
import gzip
import io
import json
import os
import re
import sys
import templates
import urllib
import urllib.parse as urlparse
import urllib.request as urlrequest
import utilities
import warnings
from blmanager import BLManager
from ipaddress import IPv4Network, ip_address
from collections import OrderedDict
from contextlib import redirect_stdout
from datetime import datetime
from mimetypes import guess_type
from multiprocessing import Pool
from time import time
from utilities import logger as Logger
from utilities import ProcessingError
# load required 3rd party libraries
try:
    import whois
except:
    sys.exit(templates.LOAD_ERROR.format(u'python-whois',
                            u'https://pypi.org/project/python-whois/',
                            ))
try:
    import ipwhois
except:
    sys.exit(templates.LOAD_ERROR.format(u'ipwhois',
                            u'https://pypi.org/project/ipwhois/',
                            ))
try:
    from dns import resolver as dnsresolver
except:
    sys.exit(templates.LOAD_ERROR.format(u'dnspython',
                            u'https://pypi.org/project/dnspython/',
                            ))
try:
    from strsimpy.jaro_winkler import JaroWinkler as JWIN
    from strsimpy.ngram import NGram
except:
    sys.exit(templates.LOAD_ERROR.format(u'strsimpy',
                            u'https://pypi.org/project/dnspython/',
                            ))
""" Copyright
#
#  Copyright 2022   Software Engineering Institute @
#                   Carnegie Mellon University
#                    Donald Ranta <dmranta>[@]<cert>.<org>]
#
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#
#######################################################################
"""

""" Parameters
#######################################################################

    File Name:      stcompare.py
    Created:        April 19, 2022
    Author:         <dmranta>[@]<cert.org>

    Description:    Uses the Security Trails API to download a daily
                    list of "New Domains" and compares those domains
                    against a list of "Known" company/domain strings to
                    evaluate similarity using Jaro-Winkler
                    similarity scoring. The following command line
                    parameters are available to "fine tune" comparison
                    processing:

                    -k, --knowns_file - Path to the file containing "known"
                            strings to compare. If knowns file path
                            is not provided, the application will try
                            to use a "knowns.txt" file in the "knowns"
                            subdirectory under the application directory
                    -t, --target_file - Path to the file containing "target" '\
                            strings to compare to knowns. If a target '\
                            file is not provided the application will '\
                            retrieve the daily "new domains" list from '
                            Security Trails.
                    -j, --jaro - Minimum string similarity (Jaro-Winkler)
                            threshold. Range: 1-100 (DEFAULT:92)
                    -o, --output_type - Output results in designated
                            format (csv|html|json) (DEFAULT: html)
                    -u, --unattended - Applicattion cannot accept user
                            input, e.g. cron jobs. True|False (DEFAULT: False)
                    --autoclean - Automaticlly remove retrieved files older
                            than the threshold defined by --days_saved.
                            (DEFAULT: 10)
                    --field_index - Index of field in CSV file to
                            compare. Starting with "0" (DEFAULT:0)
                    --display - Open collected results file in
                            corresponding application (DEFAULT: True)
                    --errors_out - Display error message to console for
                            errors encountered that do NOT terminate
                            processing. True|False (DEFAULT: False)
                    --known_min - The minimum allowable length for a
                            "known" string. (DEFAULT: 3)
                    --dns_server - The IP address of the server to use
                            for dns lookups (DEFAULT: 8.8.8.8)
    Syntax:         Use "[python3] stcompare.py -h" at command line to
                        see application help and syntax

#######################################################################
"""

""" Versioning
#######################################################################
    2022-04-19  v0.1    Initial test release
    2022-05-16  v0.2    Limited cpu usage to a maximum of 8 processors
                        Corrected handling of boolean command line
                        parameters
    2022-05-18   v0.3   Changed console updates from stderr to stdout
                        and included threshold values in output
                        Added Jaro-Winkler string similarity
                        comparison
                        Changed matching criteria to require that all
                        similarity scores meet minimum thresholds
                        Changed "Combined Score" to weight all 3
                        similarity scores equally
    2022-05-23  v.0.4   Replaced string similarity scoring to support
                        Jaro-Winkler similary instead of Cosine & NGram
                        Added addiional weighting for "target" strings that
                        start with or end with the "known" string
                        Added whois lookups for domain names that meet
                        similarity threshholds.
                        Added IP lookups for domain names that meet
                        similarity threshholds.
                        Added whois lookups for identified IP addresses
                        Reordered displayed output
                        Added ability to display|supress error messages
                        for exceptions that do NOT terminate processing
    2022-05-26  v0.5    Added AbuseIP IP address  and inclusion.
                        Changed JSON conversion to correctly handle
                        conversion of stored datetime objects to strings.
                        Added error logging to file.
                        Added retrieved file "cleanup" capability.
                        Added "--dns_server" parameter to specify use
                        of a specific DNS server.
    2022-05-31  v0.5.1  Corrected "gzip" file read issue
                        Created lookup for "non-routable" ip addresses
                        Made adjustments to exception handling output
    2022-06-03  v0.6    Integrated BLManager block list queries results
                        to output
                        Re-wrote logging function to distinguish errors
                        from process logging
    2022-06-13  v0.7    Integrated updates from "utilities & templates"
    2022-07-05  v1.0    Implemented with Threat Manager V1.0
    2022-07-13  v1.1    Added a "blocklist manager" object property to
                        the Processor object rather than instantiating
                        BLManager every time an external lookup was
                        required
    2022-07-14  v1.2    Added VirusTotal and GreyNoise content lookups
                        Changed settings to automate removal of files
                        retrieved from ST after 5 days
                        Reordered AbuseIPDB & Virustotal results content
                        to support column sorting
#######################################################################
"""

__meta__ = {u'title': u'Security Trails Newly Registered '\
                        u'Domain Name Comparison',
            u'longname': u'Security Trails',
            u'shortname': u'stcompare',
            u'version': u'1.2',
            u'author': u'Donald M. Ranta Jr.',
            u'copyright':u'Software Engineering Institute @ '\
                            u'Carnegie Mellon University'}


class Processor(object):
    OUTPUT_TYPES = [u'csv', u'html', u'json']
    ST_HTTP_METHOD = u'GET'
    COMMON_TLDS = [u'co', u'com', u'edu', u'gov', u'mil', u'net', u'org']
    API_SOURCES = [u'securitytrails', u'abuseip']
    # Constants for generating output
    FIELD_NAMES = [u'Original Known',
                    u'Known Permutation',
                    u'Evaluated String',
                    u'Similarity Score',
                    u'New Domain',
                    u'Domain Whois',
                    u'IP Address',
                    u'IP Whois',
                    u'Internal Block List',
                    u'DNSBL',
                    u'AbuseDBIP',
                    u'VirusTotal',
                    u'GreyNoise']

    def __init__(self,
                knowns_file=u'',
                target_file=u'',
                jaro_min=90,
                field_index=0,  # field index in CSV file
                output_type=u'html',
                unattended=False,
                autoclean=False,
                days_saved=10,
                csv_delimiter=u',',
                csv_quotechar=u'"',
                known_min=3,  # minimum allowable length of "known" string
                errors_out=True,  # display bnon-critical errors in terminal
                dns_server=None):  # DNS server to use other than default

        try:
            self.unattended = unattended
            if not self.unattended:
                _msg = u'Configuring comparator object...'
                utilities.standard_out(_msg, False)
            self.app_path = os.path.abspath(os.path.dirname(__file__))
            self.configpath = os.path.join(self.app_path, u'config')
            self.apiconfigfile = os.path.join(self.configpath, u'keys.ini')
            self.apirequired = u'securitytrails'
            self.apioptional = [u'abuseip', u'virustotal', u'greynoise']
            self.knowns_file = knowns_file.strip()
            self.target_file = target_file.strip()
            self.jaro_min = int(jaro_min)
            self.known_min = known_min
            self.field_index = int(field_index)
            self.autoclean = autoclean
            self.days_saved = days_saved
            self.csv_delimiter = csv_delimiter
            self.csv_quotechar = csv_quotechar
            if dns_server and dns_server.strip():
                self.dns_server = dns_server.strip()
            else:
                self.dns_server = None
            if self.unattended:  # always False when "unattended"
                self.errors_out = False
            else:
                self.errors_out = errors_out
            self.output_type = output_type.strip().lower()
            if self.output_type not in self.OUTPUT_TYPES:
                _errmsg = u'The specified output type: {0} is not supported.'
                raise ValueError(_errmsg.format(self.output_type))
            self.json_out = False
            if self.output_type == u'json':
               self.json_out = True
            # instantiate dnspython Resolver object
            # create list to hold ip range that can't be
            # identified with "startswith" and should be ignorred
            self.excluded_ips = utilities.cidr_to_iprange(u'172.16.0.0/12',
                                                            False,
                                                            __meta__[u'shortname'])
            # Load API parmeters from INI file
            if not self.unattended:
                _mag = u'Loading required and optional API keys...'
                utilities.standard_out(_msg)
            try:
                self.apiconfig = utilities.load_api_info(self.apiconfigfile,
                                                        self.apirequired,
                                                        self.apioptional)
            except Exception as err:
                _errmsg = u'>>>APIKeyError Exception: "{0}". Exiting...'\
                            u''.format(str(err))
                sys.exit(_errmsg)
            if self.unattended:  # always False when "unattended"
                self.errors_out = False
            else:
                self.errors_out = errors_out
            self.output_type = output_type.strip().lower()
            if self.output_type not in self.OUTPUT_TYPES:
                _errmsg = u'The specified output type: {0} is not supported.'
                raise ValueError(_errmsg.format(self.output_type))
            # define/create all required directories
            if self.knowns_file:
                self.knowns_file = os.path.abspath(self.knowns_file)
            else:
                self.knowns_dir = os.path.join(self.app_path,
                                                u'knowns',__meta__[u'shortname'])
                if not os.path.exists(self.knowns_dir):
                    os.makedirs(self.knowns_dir)
                self.knowns_file = os.path.join(self.knowns_dir,
                                                u'knowns.txt')
                if not os.path.exists(self.knowns_file):
                    with open(self.knowns_file, 'a') as f_in:
                        pass
            self.retrieved_dir = os.path.join(self.app_path,
                                                u'retrieved', __meta__[u'shortname'])
            if not os.path.exists(self.retrieved_dir):
                os.makedirs(self.retrieved_dir)
            self.results_dir = os.path.join(self.app_path,
                                            u'results', __meta__[u'shortname'])
            if not os.path.exists(self.results_dir):
                os.makedirs(self.results_dir)
            # load "known" strings and "target" strings
            self.knowns = self._load_knowns()
            self.targets = self._load_targets()
            self.blocklist = BLManager(unattended=True)
            self.blocklist.update()
            self.blocklist.unattended = False
        except Exception as err:
            raise err

    def _compare(self):
        """
        manager method for comparing all knowns to all taet strings
        """
        _method = u'_compare'
        _output = {}
        try:
            # make sure the "knowns" list is populated
            if self.knowns:
                # provide metrics to user
                _knowncount = 0
                for _original in self.knowns:
                    _knowncount += len(self.knowns[_original])
                # use process count equal to 1 less than processor count
                _cpucount = os.cpu_count()-1
                if not _cpucount:
                    _cpucount = 1
                elif _cpucount > 8:
                    _cpucount = 8
                if not self.unattended:
                    # notify user
                    _msg = u'{0} - Ver. {1}\n{2}'.format(
                            __meta__[u'title'],__meta__[u'version'],
                            u'='*72)
                    utilities.standard_out(_msg)
                    _msg = u'String Similarity Threshhold: '\
                                        u'{0}'.format(self.jaro_min)
                    utilities.standard_out(_msg)
                    _msg = u'Count of Known Strings (w/permutations): '\
                                        u'{0}'.format(_knowncount)
                    utilities.standard_out(_msg)
                    _msg = u'Count of Target Strings: {0}\n'.format(
                                                        len(self.targets))
                    utilities.standard_out(_msg)
                    _msg = u'Using {0} of {1} available processors.'\
                            u''.format(_cpucount, os.cpu_count())
                    utilities.standard_out(_msg)
                    _calcs = len(self.targets) * _knowncount
                    _msg = u'Evaluations to Perform: {0}'.format(
                                                _calcs)
                    utilities.standard_out(_msg)
                    _msg = u'Comparison Processing Started: {0}'\
                            u''.format(datetime.now().isoformat().split(u'.')[0])
                    utilities.standard_out(_msg)
                try:
                    # create "output" dictionary object
                    _output = {u'created': datetime.now().isoformat(),
                                u'knowns_file': os.path.basename(self.knowns_file),
                                u'target_file': os.path.basename(self.target_file),
                                u'jaro_winkler_threshold': self.jaro_min,
                                u'knowns_count': _knowncount,
                                u'targets_count': len(self.targets),
                                u'total_matches': 0,
                                u'results': []}
                    with Pool(_cpucount) as _pool:
                        for _result in _pool.imap(self._process_known,
                                                sorted(self.knowns.keys())):
                            # add matches for "known" string to output
                            if _result:
                                # increment match count
                                _output[u'total_matches'] += _result[u'match_count']
                                # append the new result to the output object "results"
                                _output[u'results'].append(_result)
                except ProcessingError as err:
                    raise err
        except Exception as err:
            #raise ProcessingError(err)
            raise err
        # return comparison results dictionary object
        return _output

    def _convert_to_html(self, content_header, content_rows):
        """ convert parsed json content to html format """
        # create table content
        _tablerows = []
        # build table header
        _tablehdr = utilities.create_table_header(self.FIELD_NAMES)
        # add html table content
        _tablerows.append(_tablehdr)
        try:
            for _record in content_rows:
                for _ndx in range(len(_record)):
                    _record[_ndx] = str(_record[_ndx]).strip().replace(u'\n', u'<br>')
                    
                """
                _newrecord = _record
                for x in range(len(_record):
                    _newrecord
                #_domainwhois
                #_newrecord[5] = re.sub(r'\n+', u'\n',
                #            str(_record[5])).replace(u'\n', u'<br>')
                _newrecord[5] = _record[5].replace(u'\n', u'<br>')
                #_ipaddrs
                _newrecord[6] = _record[6].replace(u' ', u'<br>')
                #_ipwhois
                #_newrecord[7] = re.sub(r'\n+', u'\n',
                #            str(_record[7])).replace(u'\n', u'<br>')
                _newrecord[7] = _record[7].replace(u'\n', u'<br>')
                #_abuseip
                #_newrecord[8] = re.sub(r'\n+', u'\n',
                #            str(_record[8])).replace(u'\n', u'<br>')
                _newrecord[5] = _record[5].replace(u'\n', u'<br>')
                #_blocklist
                _newrecord[9] = re.sub(r'\n+', u'\n',
                            str(_record[9])).replace(u'\n', u'<br>')
                """

                #_newrow = utilities.create_table_row(_newrecord)
                _newrow = utilities.create_table_row(_record)
                _tablerows.append(_newrow)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_convert_to_html',
                                                type(err).__name__,
                                                str(err))
            raise ProcessingError(err, _errmsg)
        # build out html page
        # create html page header
        _hdrrows = [u'<hr>']
        for _param in content_header:
            _hdrrows.append(utilities.create_header_row(_param,
                                            content_header[_param]))
        _contenthdr = templates.CONTENT_HEADER.format(
                                                __meta__[u'title'],
                                                u' '.join(_hdrrows))
        # generate html results table
        _htmltable = templates.HTML_TABLE.format(u'\n'.join(_tablerows))
        # create html page footer
        _pagefooter = templates.PAGE_FOOTER.format(__meta__[u'version'],
                                                __meta__[u'copyright'],
                                    datetime.today().strftime('%Y'))

        # combine all html components
        _htmlout = templates.HTML_BASE.format(__meta__[u'title'],
                                                templates.PAGE_STYLE,
                                                templates.JAVA_SCRIPT,
                                                _contenthdr,
                                                _htmltable,
                                                _pagefooter)
        # return the newly constructed html page
        return _htmlout

    @staticmethod
    def _convert_to_rows(results):
        # convert JSON to header info & content rows
        try:
            _contentheader = {}
            for _key in results:
                if _key != u'results':
                    _contentheader[_key] = results[_key]
            _contentrows = []
            for _match in results[u'results']:
                _newrows = []
                for _known in _match[u'matches']:
                    for _newmatch in _match[u'matches'][_known]:
                        _newrow = [_match[u'known_string']]
                        _newrow.append(_known)
                        for _key in _newmatch:
                            _value = _newmatch[_key]
                            if _value is None:
                                _value = u''
                            _objtype = type(_value)
                            if _objtype is list:
                                _data = [str(_entry) for _entry in _value]
                                _value = u' '.join(_data)
                            elif _objtype is dict:
                                _value = u''
                                for _entry in _newmatch[_key]:
                                    _data = _newmatch[_key][_entry]
                                    if type(_data) is list:
                                        _data = [str(_entry) for _entry in _data]
                                        _data = u' '.join(_data)
                                    _value += u'{0}: {1}\n'.format(
                                                            _entry,
                                                            _data)
                            _newrow.append(_value)
                        _newrows.append(_newrow)
                _contentrows.extend(_newrows)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_convert_to_rows',
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)
        return {u'content_header': _contentheader,
                    u'content_rows': _contentrows}

    def _evaluate_scores(self, known, target):
        """ calculate similarity scores for known--> target pair """
        try:
            _record = None
            # add weight to fully included knowns
            _included = ((target.startswith(known) or
                            target.endswith(known)) and
                        (len(target)/len(known) <= 2.5))
            # jaro-winkler similarity
            _jaro = JWIN()
            _jarosim = _jaro.similarity(known, target)
            if _included:
                # add 2.5% if target startswith or ends with known
                _weighted = _jarosim * 1.025
                if not _weighted > 1.0:
                    _jarosim = _weighted
            if _jarosim >= self.jaro_min/100.0:
                _record = {u'evaluated': target,
                            u'similarity_score': round(_jarosim * 100.0, 2),
                            u'domain_name': None,
                            u'domain_whois': None,
                            u'ip_address': None,
                            u'ip_whois': None
                            }
        except Exception as err:
            raise err
        # return record dictionary
        return _record

    def _load_knowns(self):
        """
            Read in contents of the "knowns" file, and
            generate permutations of knowns for evaluation
        """
        _lines = []
        if (not os.path.exists(self.knowns_file) or
            not os.path.isfile(self.knowns_file) or
            not os.access(self.knowns_file, os.R_OK)):
            raise ValueError(u'The "knowns" file provided: {0} is NOT '\
                                u'a file, is not accessible, or does '\
                                u'not exist.'.format(self.knowns_file))
        try:
            if not self.unattended:
                _msg = u'Loading "knowns" file: {0}'.format(self.knowns_file)
                utilities.standard_out(_msg)
            with open(self.knowns_file, 'rt')as f_in:
                _data = f_in.readlines()
            _lines = []
            for _line in _data:
                _newline = _line.strip().lower()
                if (len(_newline) >= self.known_min and
                        not _newline.startswith(u'#')):
                    _lines.append(_newline)
            _knowns = {}
            if len(_lines):
                for _line in _lines:
                    _knowns[_line] = []
                    _newline = re.sub(r'\.((com)|(net)|(org)|(edu)|(us)|(biz)|'\
                                        r'(gov))$', u'',
                                        _line.lower(), 0, re.I)
                    _newline = re.sub(r'\x20((and)|&|(of))\x20', u'',
                                        _newline, 0, re.I)
                    _newline = re.sub(r"(\-|&|\.|\,|\_|\x20|')", u'',
                                        _newline, 0, re.I)
                    if _newline not in _knowns[_line]:
                        _knowns[_line].append(_newline)
                    for _permutation in self._permutate_known(_newline):
                        if (_permutation and _permutation
                                not in _knowns[_line]):
                            _knowns[_line].append(_permutation)
                            for _new in self._permutate_known(_permutation):
                                if _new and _new not in _knowns[_line]:
                                    _knowns[_line].append(_new)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_load_knowns',
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)
        if not _knowns:
            sys.exit(u'-->ATTENTION: No "known" strings loaded '\
                                u'from file: "{0}". Exiting...\n'.format(self.knowns_file))
        # return list of "known" domain name strings
        return _knowns

    def _load_targets(self):
        """ load target string from indicated file or download from ST """
        _method = u'_load_targets'
        _targets = None  # dict of target values with adjusted values
        f_in = None
        try:
            try:
                if not self.target_file:
                    _retrieve = self._load_targets_verify()
                    if _retrieve == u'web':  # Retrieve data through ST API
                        if not self.unattended:
                            _msg = u'Retrieving new domain strings '\
                                    u'from Security Trails...'
                            utilities.standard_out(_msg)
                        _data = self._retrieve_data()
                        if _data:
                            with open(self.target_file, 'wb') as f_out:
                                f_out.write(_data)
                        else:
                            # No data retrieved from ST
                            sys.exit(u'No data retrieved from Security Trails.'\
                                        u'Exiting...\n')
                    elif _retrieve == u'local':
                        # means process existing previously retrieved file
                        pass
                    else:
                        sys.exit(u'Security Trails "New Domains" data '\
                                    u'retrieval aborted. Exiting...\n')
                else:  # a target file path was provided at the command line
                    self.target_file = os.path.abspath(self.target_file)
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
                raise ProcessingError(err, _errmsg)
            if (self.target_file and
                (not os.path.exists(self.target_file) or
                    not os.access(self.target_file, os.R_OK))):
                raise ValueError(u'The target file: {0} '\
                                    u'is not accessible or does not '
                                    u'exist\n'.format(self.target_file))
            elif not self.target_file:
                _errmsg = u'A required "target file" for processing '\
                            u'has not been defined. Exiting...\n'
                sys.exit(_errmsg)
            if not self.unattended:
                _msg = u'Loading new domain strings...'
                utilities.standard_out(_msg)
            # file exists, process the contents assume gzip to start
            _mimetype = u'gzip'
            _encoding = u'utf-8'
            try:
                _encoding, _mimetype = guess_type(self.target_file)
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(u_method,
                                                    type(err).__name__,
                                                    str(err))
                raise ProcessingError(err, _errmsg)
            try:
                if _mimetype == u'gzip':
                    f_in = gzip.open(self.target_file,
                                        mode=u'rt')
                elif _mimetype in [u'text/csv', u'text/plain']:
                    f_in = open(self.target_file, 'rt')
                elif _mimetype == u'application/vnd.ms-excel':
                    f_in = open(self.target_file, 'rb')
                else:
                    _errmsg = u'The file type: {0} of target file: {1}'\
                                u'is not supported.'.format(_mimetype,
                                                            self.target_file)
                    raise TypeError(_errmsg)
                # insure pointer is at start of file
                f_in.seek(0)
            except TypeError as err:
                raise err                
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
                raise ProcessingError(err, _errmsg)
            if f_in:
                try:
                    # create CSv reader object
                    _reader = csv.reader(f_in, delimiter=self.csv_delimiter,
                                            quotechar=self.csv_quotechar)
                    _targets = {}
                    for _row in _reader:
                        _newtarget = _row[self.field_index].strip().lower()
                        if (len(_newtarget) >= self.known_min and
                                not _newtarget.startswith(u'#')):
                            _targets[_newtarget] = self._parse_target(
                                                            _newtarget)
                except Exception as err:
                    raise err
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)
        finally:
            # close the open file handle
            if f_in:
                f_in.close()
        # return sorted target string dictionary
        return OrderedDict(sorted(_targets.items()))

    def _load_targets_verify(self):
        """ verifies existance of target file or retreival from ST """
        _retrieve = u'abort'
        try:
            _today = datetime.now().isoformat().split(u'T')[0]
            # construct file name for persisted source content
            _filename = u'{0}-{1}.gz'.format(__meta__[u'shortname'], _today)
            # store the file is appropriate directory
            self.target_file = os.path.join(self.retrieved_dir, _filename)
            _fileexists = os.path.exists(self.target_file)
            if not self.unattended:
                if not _fileexists:
                    _msg = u'A "New Domains" file for today does '\
                            u'not exist.'
                    utilities.standard_out(_msg)
                    _input = u''
                    while _input not in utilities.YESNO:
                        _msg = u'Retrieve today\'s daily'\
                                        u'"New Domains" file '\
                                        u'from Security Trails? '\
                                        u'[Y|N] '
                        _input = utilities.standard_out(_msg, True).strip()[0].upper()
                    if _input == u'Y':
                        _retrieve = u'web'
                    else:
                        sys.exit(u'Processing aborted by user. '\
                                    u'Exiting...\n')
                else:
                    _msg = u'A "New Domains" file for today already '\
                            u'exists.'
                    utilities.standard_out(_msg)
                    _getnew = u''
                    while _getnew not in utilities.YESNO:
                        _msg = u'Retrieve and update the '\
                                u'existing file?\n'\
                                u'(uses an additional query credit) [Y|N] '
                        _getnew = utilities.standard_out(_msg, True).strip()[0].upper()
                        if _getnew == u'N':
                            _continue = u''
                            while _continue not in utilities.YESNO:
                                _msg = u'Continue processing with '\
                                                u'the existing file? '\
                                                u'[Y|N] '
                                _continue = utilities.standard_out(_msg, True).strip()[0].upper()
                            if _continue == u'N':
                                self.target_file = None
                                _retrieve = u'abort'
                            else:
                                _retrieve = u'local'
                        else:
                            _retrieve = u'web'
            else:  # unattended operation
                _retrieve = u'web'
            if not self.unattended or self.autoclean:
                # clean up old retrieved files if desired
                _cleanup = u''
                if self.autoclean:
                    _cleanup = 'Y'
                while _cleanup not in utilities.YESNO:
                    _msg = u'Remove any previously retrieved '\
                                        u'files older than {0} '\
                                        u'days old? '.format(self.days_saved)
                    _cleanup = utilities.standard_out(_msg, True).strip()[0].upper()
                if _cleanup == u'Y':
                    self._retrieved_cleanup()
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_load_targets_verify',
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)
        # return path to "target" file
        return _retrieve

    def _parse_target(self, input_line):
        """ adjusts target string to remove commaon TLDs etc """
        _method = u'_parse_target'
        _target = input_line.strip().lower()
        try:
            try:
                # decode byte string
                _target = _target.decode()
            except AttributeError:
                pass
            # check to see if target string matches domain regex
            _domain = utilities.REGEX_DOMAIN.match(_target)
            # if so, split domain name into parts
            if _domain:
                _parts = _target.split('.')
                # determine TLDs/SLDs to remove
                _ndx = len(_parts)
                while _ndx:
                    _ndx -= 1
                    if (_parts[_ndx] in self.COMMON_TLDS or
                            len(_parts[_ndx]) < 3):
                        continue
                    else:
                        break
                # retain everything else
                _target = '.'.join(_parts[:_ndx+1])
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            pass
        # return parsed target value
        return _target

    def _permutate_known(self, input_string):
        """
            Creates permutations of the "known" string by removing
            commonly included terms from the end of the "known"
            string, and retaining all variants for evaluation
        """
        _method = u'_permutate_known'
        _excluded = [
                    r'^the\s',
                    r'ltd$',
                    r'(p|l)lc$',
                    # r 'lp$',
                    # r 'spa',
                    r'inc(orporated)?$',
                    r'co(mpany)?$',
                    r'corp(oration)?$',
                    r'international$',
                    r'technolog(y|ies)$',
                    r'laborator(y|ies)$',
                    r'industries$',
                    r'construction$',
                    r'communications$',
                    r'group$',
                    r'systems?$',
                    r'suppl(y|ies)$',
                    r'services?$',
                    r'holdings?$',
                    r'solutions?$',
                    # r'research$',
                    r'contracting$'
                    ]
        try:
            _next = input_string
            for _exclude in _excluded:
                _next = re.sub(_exclude, u'', _next, 0, re.I)
                if len(_next) >= self.known_min:
                    yield _next
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            pass

    def _persist_results(self, results):
        _method = u'_persist_results'
        try:
            _content = None
            if self.output_type == u'json':
                _content = json.dumps(results,
                                        indent=2,
                                        default=utilities._json_val2str)
            elif self.output_type in [u'csv', u'html']:
                _converted = self._convert_to_rows(results)
                if self.output_type == u'csv':
                    _content = utilities.create_csv_content(_converted)
                elif self.output_type == u'html':
                    _content = self._convert_to_html(
                                        _converted[u'content_header'],
                                        _converted[u'content_rows'])
            # build path to output file
            _outfile = u'{0}-{1}.{2}'.format(__meta__[u'shortname'],
                                            utilities.day_of_week(),
                                            self.output_type)
            # define output file path variable
            _outputfile = None
            # write formatted content to output file
            if _content:
                _outputfile = os.path.join(self.results_dir, _outfile)
                with open(_outputfile, 'wt') as f_out:
                    f_out.write(_content)
        except ProcessingError as err:
            raise err
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            raise ProcessingError(err, _errmsg)
        # return path to output file
        return _outputfile

    def _process_known(self, original):
        """ compare known permutations against target strings """
        _method = u'_process_known'
        _matches = {u'known_string': original,
                    u'match_count': 0,
                    u'matches': {}}
        _count = 0
        try:
            for _known in self.knowns[original]:
                try:
                    _matched = []
                    for _domain in self.targets:
                        try:
                            _match = self._evaluate_scores(_known,
                                                self.targets[_domain])
                        except Exception as err:
                            _errmsg = templates.ERROR_GENERIC.format(
                                                u'process_known:_evaluate_scores',
                                                type(err).__name__,
                                                str(err))
                            Logger(__meta__[u'shortname'], u'process_known:_evaluate_scores',
                                    _errmsg, err, self.unattended, self.errors_out)
                            continue
                        try:
                            if _match and _match not in _matched:
                                #_count += 1
                                _match[u'domain_name'] = _domain
                                _ipaddrs = []
                                try:
                                    _match[u'domain_whois'] = utilities.retrieve_WhoIs([_domain])
                                    _ipaddrs = utilities.retrieve_domain_ips(_domain)
                                except Exception as err:
                                    _errmsg = templates.ERROR_GENERIC.format(
                                                    u'process_known:_retrieve_domain_whois',
                                                    type(err).__name__,
                                                    str(err))
                                    Logger(__meta__[u'shortname'], u'process_known:_retrieve_domain_whois',
                                            _errmsg, err, self.unattended, self.errors_out)
                                    continue
                                _match[u'ip_address'] = _ipaddrs
                                _match[u'ip_whois'] = None
                                _match[u'internal_bl'] = None
                                _match[u'dnsbl'] = None
                                _match[u'abuseipdb'] = None
                                _match[u'virustotal'] = None
                                _match[u'greynoise'] = None
                                if _ipaddrs:
                                    # WhoIs lookups
                                    _match[u'ip_whois'] = utilities.retrieve_WhoIs(_ipaddrs)
                                    # AbuseIPDb lookups
                                    _match[u'abuseipdb'] = utilities.retrieve_AbuseIPDB(
                                                            addresses = _ipaddrs,
                                                            api_key = self.apiconfig[u'abuseip'][u'apikey'],
                                                            json_out = self.json_out,
                                                            unattended = self.unattended)
                                    # Internal Blocklist lookups
                                    _results = []
                                    for _ipaddr in _ipaddrs:
                                        try:
                                            _qtype = utilities.determine_query_type(_ipaddr)
                                            _data = self.blocklist._query_internal_bl(_ipaddr, _qtype)
                                            if _data:
                                                _results.append(_data)
                                        except Exception as err:
                                            _errmsg = templates.ERROR_GENERIC.format(
                                                            u'process_known:ip_blocklist_query',
                                                            type(err).__name__,
                                                            str(err))
                                            Logger(__meta__[u'shortname'], u'process_known:ip_blocklist_query',
                                                    _errmsg, err, self.unattended, self.errors_out)
                                            pass
                                    _match[u'internal_bl'] = u'\n\n'.join(_results)
                                    # VirusTotal lookups                                    
                                    _match[u'virustotal'] = utilities.retrieve_VT_IP(
                                                                addresses = _ipaddrs,
                                                                api_key=self.apiconfig[u'virustotal']['apikey'],
                                                                json_out=self.json_out)
                                    # GreyNoise lookups                                    
                                    _match[u'greynoise'] = utilities.retrieve_GreyNoise(
                                                            addresses = _ipaddrs,
                                                            api_key=self.apiconfig[u'greynoise']['apikey'],
                                                            json_out=self.json_out)
                                    # DNSBL Lookups
                                    _match[u'dnsbl'] = utilities.retrieve_DNSBL(addresses = _ipaddrs,
                                                        json_out=self.json_out)
                                _matched.append(_match)
                                #_count += 1
                        except ProcessingError as err:
                            raise err
                        except Exception as err:
                            import traceback
                            traceback.print_exc(file=sys.stdout)
                            _errmsg = templates.ERROR_GENERIC.format(
                                                    _method,
                                                    type(err).__name__,
                                                    str(err))
                            Logger(__meta__[u'shortname'], _method, _errmsg, err,
                                    self.unattended)
                            continue
                    if _matched:
                        _matches[u'matches'][_known] = _matched
                        _matches[u'match_count'] += len(_matched)
                except ProcessingError as err:
                    raise err
                except Exception as err:
                    _errmsg = templates.ERROR_GENERIC.format(
                                            _method,
                                            type(err).__name__,
                                            str(err))
                    Logger(__meta__[u'shortname'], _method, _errmsg, err,
                            self.unattended)
                    continue
        except ProcessingError as err:
            raise err
        except Exception as err:
            raise ProcessingError(err)
        #if _count:
        #    _matches[u'match_count'] = _count
        #else:
        #    _matches = None
        # return collected matched records
        return _matches

    def _retrieve_data(self):
        """
        retrieve new domain date from Security Trails
        and persist to file
        """
        _method = u'_retrieve_data'
        _data = None
        # create "Request" object to source
        _request = None
        # construct request headers
        _reqhdrs = {u'User-Agent': utilities.USER_AGENT,
                    u'Accept': 'application/gzip'}
        _request = urlrequest.Request(
                            templates.ST_API_NEW_URL.format(
                            self.apiconfig[self.apirequired][u'apikey']))
        for _header in _reqhdrs:
            _request.add_header(_header, _reqhdrs[_header])
        _request.method = self.ST_HTTP_METHOD
        # retrieve new data file
        # connect to source and retrieve desired content
        try:
            with urlrequest.urlopen(_request) as _response:
                _status = _response.status
                if _status == 200:
                    # read in response content
                    _data = _response.read()
        except urllib.error.HTTPError as err:
            raise ProcessingError(err)
        except urllib.error.URLError as err:
            raise ProcessingError(err)
        except Exception as err:
            raise ProcessingError(err)
        # return retrieved data
        return _data

    def _retrieved_cleanup(self):
        """
            removes any retrieved Security Trails file
            more than 10 days old. user must approve
        """
        _method = u'_retrieved_cleanup'
        _count = 0
        try:
            # retrieve list of matching files
            _files = []
            for root, dirs, files in os.walk(self.retrieved_dir):
                _files = [_file for _file in files if _file.endswith(u'.gz')]
            # let user known that no files met threshold
            if not len(_files):
                if not self.unattended and not self.autoclean:
                    _msg = u'No retrieved files meet the {0} day '\
                            u'age threshold'.format(self.days_saved)
                    utilities.standard_out(_msg)
            else:
                # iterate through file list
                for _file in _files:
                    if _file.endswith(u'.gz'):
                        _filepath = os.path.join(self.retrieved_dir, _file)
                        _modified = os.path.getmtime(_filepath)
                        _now = time()
                        _age = _now - _modified
                        if _age >= 86400.0 * self.days_saved:
                            _cleanup = u''
                            if self.autoclean:
                                _cleanup = u'Y'
                            while _cleanup not in [u'Y', u'N']:
                                if not self.unattended and not self.autoclean:
                                    _cleanup = input(u'Remove retrieved file: '\
                                                        u'{0}? '.format(_file))[0].upper()
                            if _cleanup == u'Y':
                                try:
                                    if not self.unattended and not self.autoclean:
                                        _msg = u'-->Removing retrieved file: '\
                                            u'{0} ...'.format(_filepath)
                                        utilities.standard_out(_msg)
                                    os.remove(_filepath)
                                    _count += 1
                                except Exception as err:
                                    _errmsg = templates.ERROR_GENERIC.format(
                                                    _method,
                                                    type(err).__name__,
                                                    str(err))
                                    Logger(__meta__[u'shortname'], _method, _errmsg,
                                           err, self.unattended, self.errors_out)
                                    pass
                            elif not self.unattended and not self.autoclean:
                                _msg = u'Skipping retrieved file: '\
                                        u'{0}'.format(_filepath)
                                utilities.standard_out(_msg)
                if not self.unattended and not self.autoclean:
                    if not _count:
                        _msg = u'No retrieved files met the {0} day '\
                                        u'age threshold. Continuing...'\
                                        u''.format(self.days_saved)
                        utilities.standard_out(_msg)
                    else:
                        _msg = u'{0} retrieved files met the {1} day '\
                                        u'age threshold and were '\
                                        u'removed'.format(_count,
                                                        self.days_saved)
                        utilities.standard_out(_msg)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            pass
        return _count

    def process(self):
        """
        Primary method for retrieveing new content and comparing it
        to "known" strings
        """
        _method = u'process'
        _errmsg = u''
        _results = None
        _resultsfilepath = u''
        # check if block list should be update
        # instantiate block list manager object instance
        try:
            _start = time()
            try:
                if not self.unattended:
                    _msg = u'Checking age of internal blocklist data...'
                    utilities.standard_out(_msg)
                _blmanager = BLManager(unattended=self.unattended)
                _updateneeded = _blmanager.verify_bl_update()
                if _updateneeded:
                    if not self.unattended:
                        _msg = u'Internal blocklist database is out of date. '\
                                u'Updating now...'
                        utilities.standard_out(_msg)
                    _blmanager.update()
                elif not self.unattended:
                    _msg = u'Internal blocklist database is up to date. '\
                            u'Continuing...'
                    utilities.standard_out(_msg)
                # release BLManager object instnace
                _blmanager = None
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
                Logger(__meta__[u'shortname'], u'process:blocklist_update',
                        _errmsg, err, self.unattended, self.errors_out)
                pass
            try:
                # if successful, process target file content against knowns
                #utilities.standard_out(u'Knowns to compare (includes permutations): {0}'.format(len(self.knowns)), False)
                _results = self._compare()
            #except ProcessingError as err:
            #    raise err
            except Exception as err:
                #raise ProcessingError(err)
                raise err
            if _results and _results[u'total_matches']:
                try:
                    # persist results to file
                    _resultsfilepath = self._persist_results(_results)
                except ProcessingError as err:
                    raise err
                except Exception as err:
                   raise ProcessingError(err)
            _end = time()
            if not self.unattended:
                _msg = u'Actual Processing Time: {0} minutes'.format(
                                round(float(_end - _start)/60.0, 2))
                utilities.standard_out(_msg)
        except ProcessingError as err:
            raise err
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(
                                    _method,
                                    type(err).__name__,
                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err,
                    self.unattended)
            raise err
        # return the file path to the created "results" file
        return _resultsfilepath

# ######################################################################
if __name__ == '__main__':
    # import libraries necessary for command line operation
    from platform import system
    from argparse import ArgumentParser
    from subprocess import call, DEVNULL

    # instantiate argument parser
    _parser = ArgumentParser(description=__meta__[u'title'])
    _parser.add_argument(u'-k', '--knowns_file', default=u'',
                            help='Path to the file containing "known" '\
                            u'strings to compare. If knowns file path '\
                            u'is not provided, the application will try '\
                            u'to use a "knowns.txt" file in the "knowns" '\
                            u'subdirectory under the application directory.')
    _parser.add_argument(u'-t', '--target_file', default=u'',
                            help='Path to the file containing "target" '\
                            u'strings to compare to knowns. If a target '\
                            u'file is not provided the application will '\
                            u'retrieve the daily "new domains" list from '
                            u'Security Trails.')
    _parser.add_argument(u'-j', u'--jaro', type=int, default=92,
                            help='Minimum Jaro-Winkler string similarity '\
                            u'threshold. Range: 1-100 (DEFAULT: 90)')
    _parser.add_argument(u'-o', u'--output_type', type=str, default='html',
                            choices=[u'csv', u'html', u'json'],
                            help='Output results in designated format '\
                            u'(html|json|tab) (DEFAULT: html)')
    _parser.add_argument(u'-u', u'--unattended', type=str,
                            choices=[u'True', u'False'], default=u'False',
                            help='Applicattion cannot accept user '\
                            u'input, e.g. CRON job execution. '\
                            u'(DEFAULT: False)')
    _parser.add_argument(u'--autoclean', type=str,
                            choices=[u'True', u'False'],
                            default=u'True',
                            help='Automatically remove any retrieved files '\
                            u'older than the threshold defined by '\
                            u' the --days_saved parameter (DEFAULT: False)')
    _parser.add_argument(u'--days_saved', type=int, default=5,
                            help=u'The maximum age for a stored retrieved '\
                            u'file. (DEFAULT: 10)')
    _parser.add_argument(u'--field_index', type=int, default=0,
                            help='Index of field in CSV file to compare. '\
                            u'starting with "0" (DEFAULT: 0)')
    _parser.add_argument(u'--known_min', type=int, default=3,
                            help='The minimum allowable length for'
                            u'a "known" string to evaluate (DEFAULT: 3)')
    _parser.add_argument(u'--dns_server', type=str, default=u'None',
                            help=u'The IP address of the default dns '\
                            u'server to use for dns lookups, e.g. 8.8.8.8 '\
                            u'Entering "None" indicates system default. '\
                            u'(DEFAULT: None)')
    _parser.add_argument(u'--errors_out', type=str,
                            choices=[u'True', u'False'], default=u'True',
                            help='Output error messages to console. All '\
                            u'errors are logged to log files. NOTE: '\
                            u'Specifying "True" may slightly increase '\
                            u'overall processing time. (DEFAULT: True) ')
    try:
        # collect the commandline arguments
        _args = _parser.parse_args()
        if _args.jaro < 1 or _args.jaro > 100:
            sys.exit(u'The Jaro-Winkler string similarity threshold '\
                        u'MUST be between 1 and 100. Exiting...\n')
        _outtype = _args.output_type.lower()
        # calculated appropriate Python values for some parameters
        _unattended = False
        if _args.unattended == u'True':
            _unattended = True
        _errors_out = False
        if _args.errors_out == u'True':
            _errors_out = True
        _autoclean = False
        if _args.autoclean == u'True':
            _autoclean = True
        _dnsserver = _args.dns_server.strip().lower()
        if not _dnsserver or _dnsserver == u'none':
            _dnsserver = None
        try:
            # instantiate DomainCompare object
            _processor = Processor(knowns_file=_args.knowns_file,
                                    target_file=_args.target_file,
                                    jaro_min=_args.jaro,
                                    field_index=_args.field_index,
                                    output_type=_outtype,
                                    unattended=_unattended,
                                    autoclean=_autoclean,
                                    days_saved=_args.days_saved,
                                    errors_out=_errors_out,
                                    known_min=_args.known_min,
                                    dns_server=_dnsserver)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'main:initiation',
                                                    type(err).__name__,
                                                    str(err))
            sys.exit(u'{0}\nExiting...\n'.format(_errmsg))
        # retrieve new content and compare to "known" strings and return
        # the path to the "results" file
        try:
            _resultsfile = _processor.process()
        except ProcessingError as err:
            sys.exit(u'{0}\n'.format(str(err)))
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'main:process',
                                                    type(err).__name__,
                                                    str(err))
            sys.exit(u'{0}\nExiting...\n'.format(_errmsg))
        if _resultsfile and not _unattended:
            # suppress resource warnings
            warnings.filterwarnings(action="ignore")
            # let user know where logical file was created
            _msg = u'RESULTS: Comparison results saved to: '\
                                u'{0}'.format(_resultsfile)
            utilities.standard_out(_msg)
            sys.stdout.flush()
            _system = system()
            # open corresponding application for content display
            if _system == 'Darwin': # macOS
                call([u'open', _resultsfile],
                                    stdout=DEVNULL,
                                    stderr=DEVNULL)
            elif _system == 'Windows':  # Windows
                os.startfile(_resultsfile)
            else:  # linux variants
                call([u'xdg-open', _resultsfile],
                            stdout=DEVNULL,
                            stderr=DEVNULL)
        elif not _resultsfile and not _unattended:
                _msg = u'-->RESULTS:No results were identified from processing '\
                    u'target file: {0}\n'.format(_resultsfile)
                sys.exit(_msg)
    except KeyboardInterrupt:
        sys.exit('Execution interrupted by user. Exiting...\n')
    except Exception as err:
        _errmsg = templates.ERROR_GENERIC.format(u'main:unhandled',
                                                type(err).__name__,
                                                str(err))
        sys.exit(u'{0}\nExiting...\n'.format(_errmsg))
