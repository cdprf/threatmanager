#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import json
import os
import re
import sys
import templates
import utilities
try:
    import shodan
except:
    sys.exit(templates.LOAD_ERROR.format(u'shodan',
                                    u'https://pypi.org/project/shodan/'))
from datetime import datetime
from random import uniform as randfloat
from time import sleep, time
from urllib import request as urlrequest
from urllib.parse import urlencode
from urllib.error import HTTPError
from utilities import logger as Logger
from utilities import ProcessingError

""" Copyright

    Copyright 2022  Software Engineering Institute @
                    Carnegie Mellon University
                    Donald Ranta <dmranta>[@]<cert>.<org>]

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>

"""

""" Description
#######################################################################
#
#   File Name:      shscan.py
#   Created:        April 28, 2022
#   Last Edited:    June 13, 2022
#   Author:         <dmranta>[@]<cert.org>
#
#   Description:    Used to query Shodan to identify devices with
#                   vulnerabilities. Queries can be filtered using most
#                   of the defined Shodan search filters. Application
#                   supplements results by conducting queries against
#                   the NIST NVD API for CPE-associated vulnerabilites
#                   and returns matching records in one of 4 different
#                   output types
#
#                   -API KEYS-
#                   A unique Shodan API key is required for operation,
#                   and a NIST NVD API key may also be provided. This
#                   API key is used to enhance output with vulnerability
#                   information from the NIST NVD database related to the
#                   Common Platform Enumeration (CPE) specification(s)
#                   provided by the Shodan identified host vulnerability
#
#                   -QUERY VALUE(S)-
#                   The type of value to be queried can be an IP address/
#                   IP CIDR, e.g. 10.11.22.33 or 10.11.22.0/24; a hostname,
#                   e.g. disney.com, or organization name, e.g. disney
#                   and can be provided using the '-q', '--queryvalue'
#                   OR the '-f', '--inputfile' parameter.
#                   The '--inputfile' parameter allows the user
#                   to specify a line-separated text file of
#                   values to query. The provided list may include any
#                   of the 3 different query types (hostname, net, org),
#                   as the application will automatically identify the
#                   type of query to perform.
#
#                   -ADDITIONAL HELP-
#                   Use of the '-h' command line parameter will provide
#                   a list of other available command line parameters
#                   that may be used to further filter results
#
########################################################################
"""

""" Versioning
########################################################################
#
#   20220510    Ver 0.1     Original release
#   20220511    Ver 0.2     Corrected '_filepath' reference line #774
#   20220512    Ver 0.3     Added "--max_pages, "--unattended",
#                           command line parameters and associated
#                           functionality
#                           Added code to handle the Scanner object as
#                           a data service for another calling process
#                           and the Scanner object "service" property
#   20220516    Ver. 0.4    Added urlencoding to NVD CPE string query
#   20220601    Ver. 0.5    Addition of "--keyword" parameter
#   20220705    Ver. 1.0    Integration into "Threat Manager" suite
#   20220715    Ver. 1.1    Corrected issue with results paging
#   20220912    ver. 1.2    Minor bug fixes
#   20220922    ver. 1.3    Adjusted "default "maxpages" parameter
#   20220927    ver. 1.3.1  Replaced "maxpages" parameter with query
                            credits lookup and "alert" value
########################################################################
"""

__meta__ = {u'title': u'Shodan Host Vulnerability Query',
            u'longname': u'Shodan',
            u'shortname': u'shscan',
            u'version': u'1.3.1',
            u'author': u'Donald M. Ranta Jr.',
            u'copyright':u'Software Engineering Institute @ '\
                            u'Carnegie Mellon University'}


class Scanner(object):
    # create CVSS text to numeric conversion table
    CVSS_MINS = {u'low':0.1, u'med':4.0, u'high':7.0, u'critical':9.0}

    def __init__(self, parameters={},
                        creditalert =  1000,
                        unattended=False, # no user interaction
                        errors_out=True, # output error messages to console
                        service=False):  # responding to another process
                        #requestapikeys=True): # ask user to provide missing API keys
        try:
            # define "results" directory path for persisted content
            self.apppath = os.path.abspath(os.path.dirname(__file__))
            self.configpath = os.path.join(self.apppath, u'config')
            self.apiconfigfile = os.path.join(self.configpath, u'keys.ini')
            self.apirequired = u'shodan'
            self.apioptional = [u'nistnvd']
            self.resultspath = os.path.join(self.apppath,
                                    u'results', __meta__[u'shortname'])
            if not os.path.exists(self.resultspath):
                os.makedirs(self.resultspath)
            self.knownspath = os.path.join(self.apppath,
                                    u'knowns',__meta__[u'shortname'])
            if not os.path.exists(self.knownspath):
                os.makedirs(self.knownspath)
            self.knownsfile = os.path.join(self.knownspath,
                                            u'knowns.txt')
            if not os.path.exists(self.knownsfile):
                with open(self.knownsfile, 'a') as f_in:
                    pass
            self.unattended = unattended
            self.output_type = parameters[u'outputtype']
            del parameters[u'outputtype']
            # populate non-Shodan query parameters
            self.cvss = parameters[u'cvss']
            del parameters[u'cvss']
            self.start_date = None
            if parameters[u'startdate']:
                if not utilities.REGEX_DATE.match(parameters[u'startdate']):
                    sys.exit(u'The provided \'Start Date\' must be '\
                                u'formatted as "YYYY[-]MM[-]DD", '\
                                u'e.g. 2012-01-23. Exiting...')
                else:
                    self.start_date = datetime.strptime(
                                                parameters[u'startdate'],
                                                u'%Y-%m-%d').date()
            del parameters[u'startdate']
            # Load API parmeters from INI file
            try:
                self.apiconfig = utilities.load_api_info(self.apiconfigfile,
                                                        self.apirequired,
                                                        self.apioptional)
            except Exception as err:
                _errmsg = _errmsg = u'>>>APIKeyError Exception: "{0}". Exiting...'\
                                    u''.format(str(err))
                sys.exit(_errmsg)
            self.errors_out = errors_out
            if self.unattended:
                self.errors_out = False
            # indicates that request is non-console, from another process
            # if True, the application always returns json-formatted results
            self.service = service
            if self.service:
                self.unattended = True
                self.errors_out = False
                self.output_type = u'json'
            # convert string "booleans" to true boolean values
            for _arg in parameters:
                if type(parameters[_arg]) is str:
                    if parameters[_arg].lower() == u'true':
                        parameters[_arg] = True
                    elif parameters[_arg].lower() == u'false':
                        parameters[_arg] = False
            # populate the query values list
            self.query_values = {}
            # query value from --queryvalues parameter
            if parameters[u'queryvalue']:
                _valstr = parameters[u'queryvalue'].strip().lower()
                if _valstr:
                    _qtype = self._identify_input_type(_valstr)
                    if _qtype:
                        self.query_values[_valstr] = _qtype
            elif  parameters[u'inputfile']: # query value(s) from input file
                self._values_from_file(parameters[u'inputfile'])
            else:  # use defualt knowns file
                self._values_from_file()
            del parameters[u'queryvalue']
            del parameters[u'inputfile']
            # remaining parameters are used to create base query string
            self.query_params = parameters
            # instantiate the Shodan API connection object variable
            self.session = None
            #initialize query credit count
            self.querycredits = 0
            self.creditalert = creditalert #alert when value is at or below
        except Exception as err:
            raise err

    def _convert_to_html(self, rows):
        """
        Converts row-formatted data into HTML output

        param:rows      list of list objects with each entry
                        representing the fields of a single row
        """
        _method = u'_convert_to_html'
        try:
            _tablerows = []
            _hdrflag = False
            for _row in rows:
                if not _hdrflag:
                    # create table header from first row
                    _newrow = utilities.create_table_header(_row)
                    _hdrflag = True
                elif _row != rows[0]: # do not rebuild header row
                    # first create html linkss for any CVE
                    _temprow = _row
                    # domains
                    _temprow[7] = u' '.join([x for x in _row[7] if x.strip()])
                    # hostnames
                    _temprow[8] = u' '.join([x for x in _row[8] if x.strip()])
                    _cvelinks = []
                    for _link in sorted(_row[11]):
                        _cve = _link.split(u'(')[0]
                        if _cve.startswith(u'CVE'):
                            _newlink = templates.NVD_CVE_LINK.format(_cve, _link)
                        else: # handle MS Bugtraq, etc. with query
                            _newlink = templates.NVD_QUERY_LINK.format(_cve, _link)
                        _cvelinks.append(_newlink)
                    _temprow[11] = _cvelinks
                    # create html links to associated CVEs
                    _assoccves = []
                    for _link in sorted(_row[12]):
                        _nextcve = _link.split(u'(')[0]
                        if _nextcve.startswith(u'CVE'):
                            _assoccves.append(templates.NVD_CVE_LINK.format(_nextcve, _link))
                    _temprow[12] = _assoccves
                    # format and add row to table rows
                    _newrow = utilities.create_table_row(_temprow)
                if not _newrow in _tablerows:
                    _tablerows.append(_newrow)
            _htmltable = templates.HTML_TABLE.format(u'\n'.join(_tablerows))
            # create results header with query parameters
            _hdrrows = [u'<hr>']
            _hdrrows.append(utilities.create_header_row(u'Result Count',
                                                        len(_tablerows)-1))
            if self.start_date:
                _hdrrows.append(utilities.create_header_row(u'Start Date',
                                                        self.startdate))
            _hdrrows.append(utilities.create_header_row(u'CVSS',
                                                        self.cvss))
            _hdrparams = []
            for _param in sorted(self.query_params):
                if (_param == u'country' and
                    not self.query_params[_param]):
                    _hdrparams.append(utilities.create_header_row(_param,
                                                        u'All'))
                elif (self.query_params[_param] and
                    not self.query_params[_param] == u'False'):
                    _hdrparams.append(utilities.create_header_row(_param,
                                            self.query_params[_param]))
            _hdrrows.append(u' '.join(_hdrparams))
            # construct HTML page content from separate components
            _contenthdr = templates.CONTENT_HEADER.format(
                                                    __meta__[u'title'],
                                                    u'\n'.join(_hdrrows))
            _pagefooter = templates.PAGE_FOOTER.format(__meta__[u'version'],
                                        datetime.today().strftime('%Y'),
                                        __meta__[u'copyright'])
            _htmlout = templates.HTML_BASE.format(__meta__[u'title'],
                                                    templates.PAGE_STYLE,
                                                    templates.JAVA_SCRIPT,
                                                    _contenthdr,
                                                    _htmltable,
                                                    _pagefooter)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            raise ProcessingError(err, _errmsg)
        # return HTML page
        return _htmlout

    def _convert_to_rows(self, record):
        """
        Converts match "records" into row-based format. Returns a
        list of field value lists

        param:record    a dictionary object containing query matches
                        for a specific query value. Each "match"
                        is converted into an individual results "row"
                        list object
        """
        _method = u'_convert_to_rows'
        try:
            _allrows = []
            _rows = []
            for _record in record[u'matches']:
                if not _allrows:
                    _header = [u'Query Value'] #, u'Query Type']
                    _header.extend([_key for _key in _record])
                    _allrows.append(_header)
                _newrow = [record[u'original_value']]#,
                            #self.query_values[record[u'original_value']]]
                for _key in _record:
                    if type(_record[_key]) is str:
                       _newrow.append(_record[_key].replace(u',',u' ').strip())
                    else:
                       _newrow.append(_record[_key])
                if not _newrow in _rows:
                    _rows.append(_newrow)
            _allrows.extend(sorted(_rows))
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)
        # return a list object of field value lists
        _uniquerows = []
        for _row in _allrows:
            if _row not in _uniquerows:
                _uniquerows.append(_row)
        #return _allrows
        return _uniquerows

    def _extract_data(self, match, nvdapi=None):
        """
        Extracts specific data from a Shodan record match

        param: match    the full Shodan dictionary object containing
                        information for a host record that matches the
                        query performed
        """
        _method = u'_extract_data'
        # intialize output variable
        _record = None
        try:
            # populate various field variables
            _org = u''
            try:
                _org = str(match[u'org']).title()
            except KeyError:
                pass
            _server = u''
            try:
                _server = match[u'http'][u'server']
            except KeyError:
                pass
            _sslvalid = u''
            try:
                _sslvalid = match[u'ssl'][u'cert'][u'expired']
            except KeyError:
                pass
            _domains = []
            try:
                _domains = match[u'domains']
            except KeyError:
                pass
            _hostnames = []
            try:
                _hostnames = match[u'hostnames']
            except KeyError:
                pass
            _asn = u''
            try:
                _asn = match[u'asn']
            except KeyError:
                pass
            _isp = u''
            try:
                _isp = match[u'isp']
            except KeyError:
                pass
            _cves = []
            _assoccves = []
            if self.query_params[u'has_vuln']:
                if len(match[u'vulns']):
                    for _cve in match[u'vulns']:
                        _cvssmatch = match[u'vulns'][_cve][u'cvss']
                        if not _cvssmatch:
                            continue
                        _cvss = float(_cvssmatch)
                        if _cvss >= self.CVSS_MINS[self.cvss]:
                            _cvestr = u'{0} ({1})'.format(_cve, _cvss)
                            if not _cvestr in _cves:
                                _cves.append(_cvestr)
            # ########################################
            # ADD NVD CVE LOOKUPS BASED ON CPE STRINGS
            # If match has identified CVEs
            # ########################################
            if _cves:
                if nvdapi:# skip if no matching CVEs were identified
                    try:
                        # determine which version of cpe to use
                        # use ver 2.3 if available
                        if u'cpe23' in match:
                            _cpecontent = match[u'cpe23']
                            _cpeos = u'cpe:2.3:o:'
                        elif u'cpe' in match:
                            _cpecontent = match[u'cpe']
                            _cpeos = u'cpe:/o:'
                        else:
                            raise KeyError
                        for _cpestring in _cpecontent:
                            try:
                                # ignore Operating system definitions
                                if _cpestring.startswith(_cpeos):
                                    continue
                                _qryresults = self._retrieve_nvd(nvdapi,
                                                                _cpestring)
                                for _cve, _cvss in _qryresults:
                                    if _cvss >= self.CVSS_MINS[self.cvss]:
                                        _cvestr = u'{0} ({1})'.format(_cve, _cvss)
                                        if (not _cvestr in _assoccves and
                                            not _cvestr in _cves):
                                            _assoccves.append(_cvestr)
                                # 'sleep' for 0.6 seconds after each request to
                                # avoid exceeding NVD rate limit
                                sleep(0.6)
                            except Exception as err:
                                _errmsg = templates.ERROR_GENERIC.format(
                                            u'_extract_data:_retrieve_nvd',
                                                        type(err).__name__,
                                                        str(err))
                                Logger(__meta__[u'shortname'], u'_extract_data:_retrieve_nvd',
                                        _errmsg, err, self.unattended, self.errors_out)
                                continue
                    except KeyError:
                        # CPE section does not occur in match
                        pass
                    except Exception as err:
                        _errmsg = templates.ERROR_GENERIC.format(
                                            '_extract_data:_retrieve_nvd',
                                            type(err).__name__,
                                            str(err))
                        Logger(__meta__[u'shortname'], _method,
                                _errmsg, err, self.unattended, self.errors_out)
                        raise err
                # create match record dictionary object
                _record = {u'organization': _org,
                            u'location': u'{0} {1} {2}'.format(
                                            match[u'location'][u'city'],
                                            match[u'location'][u'region_code'],
                                            match[u'location'][u'country_code']),
                            u'ip_address': match[u'ip_str'],
                            u'port_number': match[u'port'],
                            u'isp': _isp,
                            u'asn': _asn,
                            u'domains': _domains,
                            u'hostnames': _hostnames,
                            u'http_server': _server,
                            u'valid_ssl': _sslvalid,
                            u'cves': _cves,
                            u'cpe-associated_cves': _assoccves,
                            u'last_seen': match[u'timestamp'].split(u'T')[0]}
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            pass
        #return collected data
        return _record

    def _identify_input_type(self, input_value):
        """
        Identifies the input_value for type (hostname, net, org)
        using regular expressions

        param:input_value   The value to determine the query type for
        """
        _type = u'org' # defaults to "organization" string
        # iterate through type regexes to determine input value type
        for _rgx in utilities.QUERY_RGXS:
            if utilities.QUERY_RGXS[_rgx].match(input_value):
                _type = _rgx
                break
        return _type

    def _persist_content(self, results):
        """
        writes query results to logical file in "[app dir]/results

        param:results   query results content in text format
        """
        _method = u'_persist_content'
        try:
            _fileext = self.output_type
            if _fileext == u'raw':
                _fileext = u'raw.json'
            # construct unique file name
            _filename = u'shscan-{0}.{1}'.format(
                                datetime.now().isoformat().split(u'.')[0],
                                                    _fileext)
            _filepath = os.path.join(self.resultspath, _filename)
            # write results to file
            with open(_filepath,u'wt') as f_out:
                f_out.write(results)
        except IOError as err:
            _errmsg = u'The output file {0} could be created. '\
                            u'Please insure you have sufficient '\
                            u'permissions.'.format(_filename)
            Logger(__meta__[u'shortname'], u'_persist_data',
                _errmsg, err, self.unattended, self.errors_out)
            raise IOError(_errmsg)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)
        # return the full path to the created results file
        return _filepath

    def _process_matches(self, matches):
        """
        Steps through matched records verifying date and
        extracting specific data

        param:matches   A list of dictionaries of Shodan query matches
        """
        _method = u'_process_matches'
        try:
            _records = []
            #retrieve NVD API key
            _nvdapikey = None
            if u'nistnvd' in self.apiconfig:
                try:
                    _nvdapikey = self.apiconfig[u'nistnvd'][u'apikey'].strip()
                except:
                    pass
            for _match in matches[1]:
                _startdate = datetime.strptime(
                                    _match[u'timestamp'].split(u'T')[0],
                                            u'%Y-%m-%d').date()
                # determine if matched record is on or after start date
                if (self.start_date and _startdate < self.start_date):
                        # not within desired date range, skip to next
                        continue
                if _match:
                    try:
                        _record = self._extract_data(_match, _nvdapikey)
                    except Exception as err:
                        _errmsg = templates.ERROR_GENERIC.format(_method,
                                                        type(err).__name__,
                                                        str(err))
                        Logger(__meta__[u'shortname'], _method, _errmsg, err,
                                self.unattended)
                if _record:
                    _records.append(_record)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)

        return {u'original_value':matches[0], u'matches':_records}

    def _generate_query_matches(self):
        """
        Retrieve matches for values in "query_values" property
        one value at a time and return matched results

        param:value     A specific string value to query the Shodan API
                        The string value, the value type and the
                        "base query" constructed during object
                        initiation are combined to create the full API
                        query string
        """
        _method = u'_generate_query_matches'
        # iterate through query values and return matched records
        for _value in sorted(self.query_values.keys()):
            _results = []
            # construct value-specific query
            _qtype = self.query_values[_value]
            _baseparams = self.query_params
            # remove automatically determined query type from base parameters
            if _qtype in _baseparams:
                del _baseparams[_qtype]
            _keyword = u''
            if u'keyword' in _baseparams:
                _keyword = u'{0} '.format(_baseparams[u'keyword'].lower())
            # build out base query string
            _basequery = u' '.join([u'{0}:"{1}"'.format(_key,
                                            str(_baseparams[_key]))
                                            for _key in _baseparams
                                            if _baseparams[_key] and
                                            _key != u'keyword'])
            # build out query string
            _qrystr = u'{0}{1}:"{2}" {3}'.format(_keyword,
                                                    _qtype,
                                                    _value,
                                                    _basequery).strip()
            try:
                # determine matching results total count
                _totalcount = self.session.count(_qrystr)[u'total']
                # if there are matching records
                if _totalcount:
                    # use floor division to determine maximum pages
                    _pages = (-(-_totalcount//100))
                    # populate counters
                    if _pages:
                        _page = 1
                        _matches = []
                        # retrieve matches a page (of 100) at a time
                        while _page <= _pages:
                            if self.querycredits < self.creditalert:
                                _errmsg = u'Remaining Query Credits: {0}'.format(self.querycredits)
                                Logger(__meta__[u'shortname'], _method, _errmsg, None, self.unattended)
                            _matches = self.session.search(_qrystr, page=_page)
                            #decrement query credit count
                            if self.querycredits > 0:
                                self.querycredits -= 1
                            _newmatches = [_record for _record
                                            in _matches[u'matches']
                                            if _record not in _results]
                            _results.extend(_newmatches)
                            # increment page counter
                            _page += 1
            except shodan.APIError as err:
                _action = u'Exiting'
                _errlwr = str(err).lower()
                if (u'unable to connect' in _errlwr or
                    u'unable to parse json' in _errlwr or
                    u'search query was invalid' in _errlwr):
                    _action = u'Skipping'
                else: # if (u'invalid api' in _errlwr or
                        # u'access denied' in _errlwr):
                    _action = u'Exiting'
                _errmsg = u'Shodan API Error: '\
                            u'"{0}" Retrieving query: '\
                            u'{1}. {2}...'.format(str(err),
                                                        _qrystr,
                                                        _action)
                if _action == u'Exiting':
                    # critical Shodan API error, exit application
                    sys.exit(u'{0}\n'.format(_errmsg))
                else:
                    Logger(__meta__[u'shortname'], _method, _errmsg, err,
                            self.unattended)
                    continue
            except ProcessingError as err:
                Logger(__meta__[u'shortname'], _method,
                        None, err, self.unattended, self.errors_out)
                raise err
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
                raise ProcessingError(err, _errmsg)
            # yield next results tuple
            yield (_value, _results)

    def _retrieve_nvd(self, api_key, cpe_string):
        """
        Retrieves CPE-associated CVEs from NIST NVD

        param:cpe_string    a cpe string obtained from the vulnerability
                            information for a query match
        """
        _method = u'_retrieve_nvd'
        _cves = []
        try:
            # create the NVD query link for the CPE string
            _nvdlink = templates.NVD_CPE_QUERY.format(api_key, cpe_string)
            _request = urlrequest.Request(_nvdlink)
            _request.add_header(u'user-agent', utilities.USER_AGENT)
            _data = None
            _cpedata = None
            # Connect to NVD and request CPE data
            try:
                with urlrequest.urlopen(_request) as url_in:
                #try:
                    _data = url_in.read()
            except HTTPError as err:
                _errmsg = u'HTTPError:{0}" occurred while retrieving '\
                    u'results for CPE: {1}'.format(str(err),
                                                    cpe_string)
                Logger(__meta__[u'shortname'], _method, _errmsg, err,
                        self.unattended, self.errors_out)
                pass
            except urllib.error.URLError as err:
                _errmsg = u'NIST NVD: {0}'.format(err.reason)
                Logger(__meta__[u'shortname'], _method, _errmsg, err,
                        self.unattended, self.errors_out)
                pass
            if _data:
                try:
                    _cpedata = json.loads(_data.decode(u'utf-8'))
                except Exception as err:
                    _errmsg = u'"{0}" error occurred during JSON conversion '\
                                u'for CPE: {1}'.format(type(err).__name__,
                                                        cpe_string)
                    Logger(__meta__[u'shortname'], _method, _errmsg, err,
                            self.unattended, self.errors_out)
                    pass
            if _cpedata and u'result' in _cpedata:
                try:
                    for _entry in _cpedata[u'result'][u'CVE_Items']:
                        # collect CVE and CVSS info
                        _cve = _entry[u'cve'][u'CVE_data_meta'][u'ID']
                        _cvss = _entry[u'impact'][u'baseMetricV2'][u'cvssV2'][u'baseScore']
                        _cves.append((_cve, _cvss))
                except KeyError:
                    pass
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            pass
        # return collected CVEs
        return sorted(_cves)

    def _values_from_file(self, file_path=u''):
        """
        loads content from the indicated "input list" file

        param:file_path     The absolute path to a line-separated
                            text file, each line containing a single
                            string value to query the Shodan API
                            The type of query to be performed is
                            determined for each value as it is loaded
                            into the object property value list
        """
        _method = u'_values_from_file'
        _filepath = file_path.strip()
        if _filepath:
            _filepath = os.path.abspath(_filepath)
        else:
            if os.path.exists(self.knownsfile):
                _filepath = self.knownsfile
            else:
                _errmsg = u'Either the "--queryvalue" or "--inputfile" '\
                        u'parameters must be provided; or the default '\
                        u'"knowns" file: {0} must must exist.\n',format(
                                                    self.knownsfile)
                raise ValueError(_errmsg)
        _listpath = u''
        _listpath = os.path.abspath(_filepath)
        # verify the file exists and is accessible
        try:
            if (not os.path.isfile(_listpath) or
                not os.path.exists(_listpath) or
                not os.access(_listpath, os.R_OK) or
                os.path.getsize(_listpath)<1):
                _errmsg = u'-->The input file indicated: "{0}" '\
                            u'is not a file, does not exist, '\
                            u'is inaccessible, or is empty.\n'.format(
                                                            _listpath)
                sys.exit(_errmsg)
            if not self.unattended:
                _msg =u'Loading "known" query values from file:\n'\
                u'{0}\n'.format(_listpath)
                utilities.standard_out(_msg)
            _qcount = 0
            with open(_listpath, 'rt') as f_in:
                for _line in f_in.readlines():
                    _newline = _line.strip().lower()
                    if (_newline and not _newline.startswith(u'#') and
                        _newline not in self.query_values):
                            #insure valid format for query type
                            _qtype = self._identify_input_type(_newline)
                            if _qtype:
                                self.query_values[_newline] = _qtype
                                _qcount += 1
            if _qcount:
                if not self.unattended:
                    _msg = u'{0} query values loaded from '\
                                        u'file.\n'.format(_qcount)
                    utilities.standard_out(_msg)
            else:
                if not self.unattended:
                    _msg = u'ATTENTION: No "known" strings loaded from '\
                    u'file: "{0}".\nExiting...\n'.format(_listpath)
                    utilities.standard_out(_msg)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, _errmsg, err, self.unattended,
                    self.errors_out)
            raise ProcessingError(err, _errmsg)
        # returns count of query values
        return _qcount

    def execute(self):
        """
        Entry point for initiating Shodan API queries using the
        parameters provided during Scanner object instance initiation.
        1. execute a query for each query value
        2. collect the returned matches
        3. convert the results into the desired output type
        4. persists collected results to file

        param:none
        """
        _method = u'execute'
        _output = None
        try:
            Logger(__meta__[u'shortname'], _method, 'Processing started',
                    None, self.unattended)
            # create list object to collect matched records
            _collection = []
            # instantiate the Shodan API connection object
            self.session = shodan.Shodan(self.apiconfig[u'shodan'][u'apikey'])
            # determine available credits
            self.querycredits = int(self.session.info()[u'query_credits'])
            _continue = True
            if self.querycredits <= self.creditalert:
                _input = u''
                while _input not in utilities.YESNO:
                    _msg = u'CAUTION: There are only {0} Shodan Query Credits remaining. '\
                            'Do you wish to continue? [Y|N]\n'.format(self.querycredits)
                    _input = input(_msg).upper()[0]
                    if _input == u'N':
                        _continue = False
            else:
                _msg = u'Shodan Query Credits remaining: {0}'.format(self.querycredits)
                utilities.standard_out(_msg, False)
            if _continue:
                # iterate through query values and return matched records
                for _record in self._generate_query_matches():
                    if _record[1]: # contains matched records
                        if self.output_type == u'raw':
                            # adds raw Shodan json to collection
                            _collection.append(_record)
                        else:
                            # extract desired field values from Shodan json
                            _result = self._process_matches(_record)
                            if self.output_type in ['csv', u'html']:
                                # converts matched "records" to row-based lists
                                _newrows = self._convert_to_rows(_result)
                                # adds matched "lists" to collection
                                _collection.extend(_newrows)
                            elif _result[u'matches']: # json
                                # add "record" dictionary objects to collection
                                _collection.append(_result)
                    # random sleep between 1/2 & 1.0 seconds to avoid
                    # exceeding shodan api rate limit of 1 per second
                    sleep(randfloat(0.5, 1.0))
            #convert collected matches into desired output format
            if _collection: #only format output if there is 1 or more rows
                if self.output_type == u'csv':
                    _output = utilities.create_csv_content(_collection)
                elif self.output_type == u'html':
                    _output = self._convert_to_html(_collection)
                elif self.output_type in [u'json', u'raw']:
                    _output = json.dumps(_collection, indent=2)
                else:
                    raise ValueError(u'The output type: {0} is not '\
                                        u'recognized.'.format(
                                                    self.output_type))
        except ProcessingError as err:
            raise err
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            Logger(__meta__[u'shortname'], _method, None, err, self.unattended,
                    self.errors_out)
            raise ProcessingError(err, _errmsg)
        # if output generated, save it to file  or return formatted json
        _process_output = None
        if _output:
            if not self.service:
                _process_output = self._persist_content(_output)
            # returns _filepath
            else:
                _process_output = json.dumps(_output, indent=2)
        Logger(__meta__[u'shortname'], _method, 'Processing ended',
                None, self.unattended)
        return _process_output


# ######################################################################
# ######################################################################
if __name__ == u'__main__':
    #import modules necesary for command line operation
    from argparse import ArgumentParser
    from platform import system
    from warnings import filterwarnings
    from subprocess import call, DEVNULL
    # ################# SHODAN API KEY ##################
    #SHODAN_API_KEY = u''
    # ################# NIST NVD API KEY ################
    #NVD_API_KEY = u''
    # ###################################################

    # instantiate argument parser and addd necessary parameters
    parser = ArgumentParser(prog=u'shscan.py',
                            description=u'Shodan API Vulnerability '\
                                        u'Query Application')
    # ##################################################################
    # ######################  QUERY PARAMETERS  ########################
    # ##################################################################
    # the specific value to query
    parser.add_argument(u'-q',u'--queryvalue', type=str,
                        default=u'',
                        help=u'The hostname, network, or organization '\
                        u'to search. If it doesn\'t match pattern for'\
                        u'hostname or network, assumes "organization"')
    # or, a file containing a list of values to query
    parser.add_argument(u'-f',u'--inputfile', type=str,
                        default=u'',
                        help=u'The path to a line-separated file containing '\
                        u'the hostname, network, or organization values '\
                        u'to query')
    parser.add_argument(u'-o', u'--outputtype',
                        choices=[u'csv', u'html', u'json', u'raw'],
                        default=u'html',
                        help=u'File format to use for output.')
    parser.add_argument(u'-k',u'--keyword', type=str,
                        default=u'',
                        help=u'A general search term to include in the '
                        u'query')
    parser.add_argument(u'-v', u'--vuln', default=u'',
                        help=u'Specific CVE, e.g. CVE-YYYY-####')
    # the following parameters are used to further filter results
    # these are used after the initial query has been executed
    parser.add_argument(u'--cvss', type=str,
                        choices=[u'low', u'med', u'high', 'critical'],
                        default='high',
                        help=u'CVSS threshold that must be met, i.e. '\
                        u'low > 0.0, med >= 4.0, high >= 7.0,'\
                        u'critical >= 9.0')
    parser.add_argument(u'--startdate', type=str, default=u'',
                        help=u'The earliest date that may be present '\
                        u'in the "lastseen" field. Date should be '\
                        u'formatted as YYYY-MM-DD, e.g. 2000-09-23')
    # ##################################################################
    # Additional SHODAN API query parameters
    # Use of these parameters constrains ALL results to matched parameter(s)
    # ##################################################################
    parser.add_argument(u'--asn', type=str, default=u'',
                        help=u'Host ASN provider identifier.' )
    parser.add_argument(u'--city', type=str, default=u'',
                        help=u'Host location city' )
    parser.add_argument(u'--country', type=str, default=u'US',
                        help=u'Host location 2 character country code. '\
                        u'Enter "All" to search all countries.')
    parser.add_argument(u'--cpe', type=str, default=u'',
                        help=u'Specific CPE string of interest.')
    #parser.add_argument(u'--device', type=str, default=u'', help=u'' )
    parser.add_argument(u'--geo', type=str, default=u'',
                        help=u'Find devices by giving geographical '\
                        u'coordinates according to certain longitudes '\
                        u'and latitudes that are within a given radius, '\
                        u'e.g. geo:32.8,-117,50 returns results within a '\
                        u'50 mile radious of San Diego California.')
    parser.add_argument(u'--has_ipv6', type=str,
                        choices = [u'True', 'False'],default='False',
                        help=u'Host has an IPv6 address assigned.' )
    parser.add_argument(u'--has_screenshot', type=str,
                        choices = [u'True', 'False'],default='False',
                        help=u'A screenshot of the page is available.')
    parser.add_argument(u'--has_ssl', type=str,
                        choices = [u'True', 'False'],default='False',
                        help=u'Host implements SSL')
    parser.add_argument(u'--has_vuln', type=str,
                        choices = [u'True', 'False'],default='True',
                        help=u'Indicates the record has an identified '\
                                u'vulnerability. Defaults to "True"')
    parser.add_argument(u'--isp', type=str, default=u'',
                        help=u'Host ISP name.' )
    #parser.add_argument(u'--link', type=str, default=u'',
    #                    help=u'')
    parser.add_argument(u'--os', type=str, default=u'',
                        help=u'Find devices based on the operating '\
                        u'system.')
    parser.add_argument(u'--port', type=int, default=0,
                        help=u'Find devices with the defined open port.')
    parser.add_argument(u'--postal', type=str, default=u'',
                        help=u'Host location postal code.')
    parser.add_argument(u'--product', type=str, default=u'',
                        help=u'Specific product implemented by host.')
    parser.add_argument(u'--region', type=str, default=u'',
                        help=u'Host location region. The 2 character '\
                        u'state code within the US.')
    parser.add_argument(u'--org', type=str, default=u'',
                        help=u'A term to match within "org" '\
                        u'(organization) field of the matched record.'
                        u'"http.component" field of the returned record.')
    parser.add_argument(u'--hostname', type=str, default=u'',
                        help=u'A term to match within the '
                        u'hostname field of the returned record')
    parser.add_argument(u'--http.server', type=str, default=u'',
                        help=u'A term to match within the '
                        u'"http.server" field of the returned record')
    # ################ application operations flags ###################
    """
    parser.add_argument(u'--max_pages', type=int, default=500,
                        help=u'The maximum number of "pages" of results '\
                                u'(100/page) for a single query to '\
                                u'retrieve. Each "page" requires 1 '\
                                u'Shodan "query credit". May be '\
                                u'overridden by user during execution.'\
                                u'Defaults to "False"')
    """
    parser.add_argument(u'--errors_out', type=str,
                            choices=[u'True', u'False'], default=u'True',
                            help='Output error messages to console. All '\
                            u'errors are logged to log files. NOTE: '\
                            u'Specifying "True" may slightly increase '\
                            u'overall processing time. (DEFAULT: False) ')
    parser.add_argument(u'--unattended', type=str,
                        choices = [u'True', 'False'],default='False',
                        help=u'Indicates no user input is available '\
                                u'Defaults to "False"')
    parser.add_argument(u'--requestapikeys', type=str,
                        choices = [u'True', 'False'],default='False',
                        help=u'Prompt user for missing API keys '\
                                u'Defaults to "True"')
    # #################################################################
    # parse out command line arguments into a dictionary
    _args = vars(parser.parse_args())
    _unattended = False
    if _args[u'unattended'] == u'True':
        _unattended = True
    del _args[u'unattended']
    _errorsout = False
    if _args[u'errors_out'] == u'True':
        _errorsout = True
    del _args[u'errors_out']
    _requestapikeys = True
    if _args[u'requestapikeys'] == u'False':
        _requestapikeys = False
    del _args[u'requestapikeys']
    # #################################################################
    # instantiate scanner object instance
    try:
        _scanner = Scanner(parameters=_args,
                            unattended=_unattended,
                            errors_out=_errorsout)
        # execute queries  and return path to output file
        _resultspath = _scanner.execute()
        if not _unattended:
            if _resultspath:
                # suppress resource warnings
                filterwarnings(action="ignore")
                # let user know where logical file was created
                _msg = u'Query results saved to: '\
                                    u'{0}\n'.format(_resultspath)
                utilities.standard_out(_msg)
                # open corresponding application for content display
                if system() == 'Darwin':       # macOS
                    call([u'open', _resultspath],
                            stdout=DEVNULL,
                            stderr=DEVNULL)
                elif system() == 'Windows':    # Windows
                    os.startfile(_resultspath)
                else:                           # linux variants
                    call([u'xdg-open', _resultspath],
                            stdout=DEVNULL,
                            stderr=DEVNULL)
            else:
                _msg = u'NO RESULTS:The submitted query did '\
                        u'not identify any results matching\n '\
                        u'the provided parameters, or the query '\
                        u'was aborted.\n\n'
                utilities.standard_out(_msg)
    except Exception as err:
        _errmsg = templates.ERROR_GENERIC.format(u'execution',
                                                    type(err).__name__,
                                                    str(err))
        raise ProcessingError(err, _errmsg)
