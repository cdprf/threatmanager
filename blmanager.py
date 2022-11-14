#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import pickle
import sys
import templates
import time
import urllib
import urllib.request as urlrequest
import utilities
from configparser import ConfigParser
from csv import reader as CSVReader
from datetime import datetime
from io import StringIO
from ipaddress import IPv4Network, IPv6Network
from ipaddress import IPv4Address, IPv6Address
from ipaddress import ip_address, ip_network
from platform import system
from shutil import copyfile
from subprocess import call, DEVNULL
from templates import ERROR_GENERIC
from time import time
from utilities import logger as Logger
from utilities import ProcessingError
from warnings import filterwarnings

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

    File Name:      blmanager.py
    Created:        June 1, 2022
    Author:         <dmranta>[@]<cert.org>

    Description:    Aggregates IP address infromation from multiple
                    publically available sourves abd aggregates them
                    in a single repository. Application automatically
                    identfies IPv4 and IPv6 addresses, as well as
                    CIDRv4 and CIDRv6 network ranges.
                    The following command line parameters are available
                    to "fine tune" comparison processing:

                    -a, --action - The type of action you would like to
                            execute with Block List Manager.
                            [query|update] (DEFAULT: query)
                    -q, --query - The value to be queried against the
                            data store. Supports IPv4 & IPv6 addresses,
                            as well as CIDRv4 and CIDRv6 network ranges.
                            REQUIRED for "query" actions, ignorred
                            for all other actions.
                    -o, --output_type - Output results in designated
                            format (csv|html|json) (DEFAULT: json)
                    -f, --filepath - The path to an file containing a line
                            separated list of IP addess/CIDR values to
                            query. This parameter must be used in
                            combination with the "-a query" parameter.
                    --config_file - Path to the Block List Manager
                            configuration file. If not provided,
                            the application defaults to configuration
                            file: <app_path>/config/blmanager.cfg.
                            Use of default config file is recommended.
                    --unattended - Applicattion cannot accept user
                            input, e.g. cron jobs. True|False
                            (DEFAULT: False)
                    --override - Override the once daily update
                            constraint (DEFAULT: False)

    Syntax:         Use "[python3] blmanager.py -h" at command line to
                        see application help and syntax

#######################################################################
"""

""" Versioning
#######################################################################

    2022-06-02  Ver 0.1 Initial release
    2022-06-10  Ver 0.2 Integrated into API Manager
    2022-06-13  Ver 0.3 Corrected block list update functionality
    2022-07-05  Ver 1.0 Implemented with Threat Manager V1.0
                        Added DNSBL, AbuseIPDb & Virustotal lookups
    2022-07-13  Ver 1.1 Minor edits to error handling and lookup
                        processing
                        Added "GreyNoise" content lookups to results
#######################################################################
"""

__meta__ = {u'title': u'IP Blocklist Query',
            u'shortname': u'blmanager',
            u'version': u'1.1',
            u'author': u'Donald M. Ranta Jr.',
            u'copyright':u'Software Engineering Institute @ '\
                            u'Carnegie Mellon University'}


class BLManager(object):

    def __init__(self,
                    config=u'',
                    query=u'',
                    list_path=u'',
                    output=u'html',
                    unattended=False,
                    override=False,):
        try:
            self.apppath = os.path.abspath(os.path.dirname(__file__))
            self.today = str(datetime.today()).split(u' ')[0]
            if config:
                self.config_file = os.path.abspath(config)
            else:
                self.config_dir = os.path.join(self.apppath,
                                                u'config')
                if not os.path.exists(self.config_dir):
                    os.makedirs(self.config_dir)
                self.config_file = os.path.join(self.config_dir,
                                                u'blmanager.cfg')
            self.config = self._load_source_config()
            self.queries = []
            if query.strip():
                self.queries.append(query.strip())
            self.list_path = list_path.strip()
            if self.list_path:
                self.list_path = os.path.abspath(list_path)
                self._load_query_list()
            self.resultspath = os.path.join(self.apppath, u'results',
                                            __meta__[u'shortname'])
            if not os.path.exists(self.resultspath):
                os.makedirs(self.resultspath)
            self.apiconfigfile = os.path.join(self.config_dir, u'keys.ini')
            self.apirequired = u''
            self.apioptional = [u'abuseip', u'virustotal', u'greynoise']
            self.apiconfig = utilities.load_api_info(self.apiconfigfile,
                                                        self.apirequired,
                                                        self.apioptional)
            self.output_type = output.lower().strip()            
            self.json_out = False
            if self.output_type == u'json':
                self.json_out = True
            self.override = override
            self.unattended = unattended
            if self.unattended:
                self.override = True
            self.lastupdatepath = os.path.join(self.apppath, u'config',
                                                u'last_bl_update.date')
            self.repo_path = os.path.join(self.apppath,
                                            u'repository', __meta__[u'shortname'])
            if not os.path.exists(self.repo_path):
                os.makedirs(self.repo_path)
            self.repo_file = os.path.join(self.repo_path, u'bl_list.bin')
            self.data_store = self._load_store()
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'__init__',
                                                type(err).__name__,
                                                str(err))
            raise ProcessingError(err, _errmsg)

    def __exit__(self):
        """ insure that the data store is persisted to file on exit """
        if self.data_store:
            self._persist_store()

    def _add_to_store(self, qtype, value, source, list_type):
        """ adds/update value to data store """
        _success = False
        try:
            # add query type to data store if not exists
            if qtype not in self.data_store.keys():
                self.data_store[qtype] = {}
            # add new value to query type dictionary in data store
            _range = None
            if value not in self.data_store[qtype].keys():
                self.data_store[qtype][value] = {u'sources':{}}
                # include start and end values of CIDR range
                if qtype.startswith(u'cidr'):
                    _range = utilities.cidr_to_iprange(value,
                                                        True,
                                                        __meta__[u'shortname'])
                    # add CIDR start and end values
                    if _range:
                        self.data_store[qtype][value][u'start'] = _range[0]
                        self.data_store[qtype][value][u'end'] = _range[1]
                        self.data_store[qtype][value][u'count'] = _range[2]
                    if not u'start_ip' in self.data_store[qtype][value]:
                        if qtype.endswith(u'4'):
                                self.data_store[qtype][value][u'start_ip'] = str(IPv4Address(_range[0]))
                                self.data_store[qtype][value][u'end_ip'] = str(IPv4Address(_range[1]))
                        else:
                            self.data_store[qtype][value][u'start_ip'] = str(IPv6Address(_range[0]))
                            self.data_store[qtype][value][u'end_ip'] = str(IPv46ddress(_range[1]))
            if (qtype.startswith(u'cidr') and
                u'count' not in self.data_store[qtype][value]):
                if _range:
                    self.data_store[qtype][value][u'count'] = _range[2]
                else:  # account for updating old records
                    self.data_store[qtype][value][u'count'] = utilities.cidr_to_iprange(value,
                                                        True,
                                                        __meta__[u'shortname'])
            if source not in self.data_store[qtype][value][u'sources']:
                self.data_store[qtype][value][u'sources'][source] = {u'date_added': self.today,
                                                            u'last_seen': self.today,
                                                            u'list_type': list_type}
            else:
                self.data_store[qtype][value][u'sources'][source][u'last_seen'] = self.today
            _success = True
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_add_to_store',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'_add_to_store', _errmsg,
                    err, self.unattended)
        # return success flag for data store update
        return _success

    def _convert_to_html(self, rows):
        """
        Converts results into HTML output

        param:rows      list of list objects with each entry
                        representing the fields of a single row
        """
        _method = u'_convert_to_html'
        try:
            # create table rows
            _tablerows = []
            _rowcount = 0
            for _row in rows:
                if not _rowcount:
                    _tablerows.append(utilities.create_table_header(_row))
                else:
                    _tablerows.append(utilities.create_table_row(_row))
                _rowcount += 1
            #create HTML table
            _htmltable = templates.HTML_TABLE.format(u'\n'.join(_tablerows))
            # create results header with query parameters
            _hdrrows = [u'<hr>']
            _hdrrows.append(utilities.create_header_row(u'Date/Time',
                                            datetime.today().isoformat()))
            _hdrrows.append(utilities.create_header_row(u'Query Count',
                                                    len(self.queries)))
            _hdrrows.append(utilities.create_header_row(u'Result Count',
                                                    len(_tablerows)-1))
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

    @staticmethod
    def _convert_to_rows(results):
        """ convert results dictionary to rows """
        _rows = []
        _fieldnames = []
        for _entry in results:
            if not _fieldnames:
                _fieldnames = [x for x in _entry.keys()]
                _rows.append(_fieldnames)
            _newrow = []
            for _key in _entry:
                _combined = u''
                _next = _entry[_key]
                if type(_next)is str and _next.strip():
                    _newrow.append(_next.strip())
                elif not _next:
                    _newrow.append(u'No Result')
                else:  # assumes dictionary
                    _value = u''
                    for _field in _next:
                        if _field == u'query':
                            continue
                        _value += u'{0}: {1}\n'.format(_field,
                                    _next[_field])
                    _newrow.append(_value)
            _rows.append(_newrow)
        return _rows

    """
    def _determine_qtype(self, query):
        # determines the format of submitted data
        _qstr = query.lower().strip()
        _qtype = None
        try:
            if u'/' in query:
                _addrobj = ip_network(query)
                _qtype = u'cidrv{0}'.format(_addrobj.version)
            else:
                _addrobj = ip_address(query)
                _qtype = u'ipv{0}'.format(_addrobj.version)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_determine_qtype',
                                            type(err).__name__,
                                            str(err))
            Logger(__meta__[u'shortname'], u'_determine_qtype', _errmsg,
                    err, True)
            pass
        return _qtype
    """
    
    def _load_source_config(self):
        """ load configuration from config file """
        _config = {}
        if (not os.path.exists(self.config_file) or
            not os.access(self.config_file, os.R_OK)):
            _msg = u'ERROR: The indicated configuration file: {0} '\
                        u'does not exist, or is inaccessible.'\
                        u'\n'.format(self.config_file)
            sys.exit(_msg)
        try:
            _parser = ConfigParser()
            _parser.read(self.config_file)
            for _source in _parser:
                _config[_source] = {}
                for _item in _parser[_source]:
                    _config[_source][_item] = _parser[_source][_item].strip('\'')
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_load_source_config',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'_load_source_config', _errmsg,
                    err, self.unattended)
            raise ProcessingError(err, _errmsg)
        return _config

    def _load_query_list(self):
        if self.list_path:
            if (os.path.exists(self.list_path) and
                os.access(self.list_path, os.R_OK)):
                with open(self.list_path, 'r') as f_in:
                    for _line in f_in.readlines():
                        _next = _line.strip()
                        if (_next and not _next.startswith(u'#') and
                            not _next in self.queries):
                            self.queries.append(_next.lower())
            else:
                _errmsg = u'The query list file path provided: {0} '\
                            u'does not exist or is inaccessible.'.format(
                            self.list_path)
                raise ValueError(_errmsg)

    def _load_store(self):
        """ loads the ip list stored in logical file """
        _repo = {}
        try:
            if os.path.exists(self.repo_file):
                # create backup of sata data store file
                copyfile(self.repo_file, u'{0}.bkp'.format(self.repo_file))
                with open(self.repo_file, 'rb') as f_in:
                    _repo = pickle.load(f_in)
            else:
                _msg = u'Block List Manager data store does not exist. '\
                        u'Loading empty data store...'
                utilities.standard_out(_msg)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_load_store',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'_load_store', _errmsg,
                    err, self.unattended)
            raise ProcessingError(err, _errmsg)
        return _repo

    def _persist_content(self, results):
        """
        writes query results to date/time named logical file in
        "[app dir]/results/blmanager"
        """
        _method = u'_persist_content'
        try:
            _fileext = self.output_type
            if _fileext == u'raw':
                _fileext = u'raw.json'
            # construct unique file name
            _filename = u'blmanager-{0}.{1}'.format(
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
            Logger(__meta__[u'shortname'], u'_persist_content',
                _errmsg, err, self.unattended, self.errors_out)
            raise IOError(_errmsg)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(_method,
                                                    type(err).__name__,
                                                    str(err))
            raise ProcessingError(err, _errmsg)
        # return the full path to the created results file
        return _filepath

    def _persist_store(self):
        """ persists the block list data store list to logical file """
        try:
            with open(self.repo_file, 'wb') as f_out:
                pickle.dump(self.data_store, f_out)            
            # create backup of sata data store file
            copyfile(self.repo_file, u'{0}.bkp'.format(self.repo_file))
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_persist_store',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'_persist_store', _errmsg,
                    err, self.unattended)
            raise ProcessingError(err, _errmsg)

    def _query(self):
        """ iterates through provided query string(s) and return results """
        _results = []
        #try:
        for _query in self.queries:
            _qtype = utilities.determine_query_type(_query)
            # retrieve information for "whois" link
            _reglink = utilities.retrieve_ip_registry(_query)
            if _reglink:
                _reglink = u'<a href="{0}" target="blank">'\
                        u'WhoIs Link</a>'.format(_reglink)
            if _reglink != None:
                _qrystr = u'{0}\n{1}'.format(_query, _reglink)
            else:
                _qrystr = _query
            #create result dictionary
            _result = {u'query': _qrystr,
                        u'internalbl': None,
                        u'dnsbl': u'unavailable',
                        u'abuseipdb': u'unavailable',
                        u'greynoise': u'unavailable',
                        u'virustotal': u'unavailable'
                        }
            # internal block list
            _result[u'internalbl'] = self._query_internal_bl(_query, _qtype)            
            if _qtype.startswith(u'ipv'):
                # query and populate external source data
                try:
                    # retrieve "abuseip" information
                    _result['abuseipdb'] = utilities.retrieve_AbuseIPDB(
                                    addresses=_query,
                                    api_key=self.apiconfig[u'abuseip'][u'apikey'],
                                    json_out=self.json_out,
                                    unattended=self.unattended)
                except Exception as err:
                    _errmsg = templates.ERROR_GENERIC.format(
                                    u'_query:retrieve_AbuseIPDB',
                                    type(err).__name__,
                                    str(err))
                    Logger(__meta__[u'shortname'], u'_query:retrieve_AbuseIPDB',
                            _errmsg, err, self.unattended, self.errors_out)
                    pass
                try:
                    # retrieve "virustotal" information
                    _result[u'virustotal'] = utilities.retrieve_VT_IP(
                                            addresses=_query,
                                            api_key=self.apiconfig[u'virustotal']['apikey'],
                                            json_out=self.json_out)
                except Exception as err:
                    _errmsg = templates.ERROR_GENERIC.format(
                                    u'_query:retrieve_VT_IP',
                                    type(err).__name__,
                                    str(err))
                    Logger(__meta__[u'shortname'], u'_query:retrieve_VT_IP',
                            _errmsg, err, self.unattended, self.errors_out)
                    pass
                try:
                    # retrieve "greynoise" information
                    _result[u'greynoise'] = utilities.retrieve_GreyNoise(
                                            addresses=_query,
                                            api_key=self.apiconfig[u'greynoise']['apikey'],
                                            json_out=self.json_out)
                except Exception as err:
                    _errmsg = templates.ERROR_GENERIC.format(
                                    u'_query:retrieve_GreyNoise',
                                    type(err).__name__,
                                    str(err))
                    Logger(__meta__[u'shortname'], u'_query:retrieve_GreyNoise',
                            _errmsg, err, self.unattended, self.errors_out)
                    pass
                # DNS blacklist lookups
                _result[u'dnsbl'] = utilities.retrieve_DNSBL(addresses=_query,
                                            json_out=self.json_out)
            # append result
            _results.append(_result)
        #except Exception as err:
        #    raise ProcessingError(err)
        return _results

    def _query_internal_bl(self, query, qtype):
        """ queries internal block list and returns matches as string """
        _result = {u'query': query,
                    u'count':0,
                    u'sources':{}}
        _matched = None
        try:
            if (qtype in self.data_store.keys() and
                query in self.data_store[qtype].keys()):
                try:
                    _matched = self.data_store[qtype][query]
                    if _matched:
                        for _key in _matched[u'sources']:
                            _matched[u'sources'][_key][u'query_type'] = qtype
                        _result[u'sources'] = _matched[u'sources']
                        _result[u'count'] += len(_matched[u'sources'].keys())
                except KeyError:
                    import traceback
                    traceback.print_exc()
                    pass
                # check for ip address in a stored CIDR range
                if qtype.startswith(u'ipv'):
                    _version = qtype[-1]
                    if _version == u'4':
                        _ip_int = int(IPv4Address(query))
                    else: # Version 6
                        _ip_int = int(IPv6Address(query))
                    _cidr = u'cidrv{0}'.format(_version)
                    for _entry in self.data_store[_cidr]:
                        if (_ip_int >= self.data_store[_cidr][_entry][u'start'] and
                            _ip_int <= self.data_store[_cidr][_entry][u'end']):
                            _cidrmatch = self.data_store[_cidr][_entry]
                            if _cidrmatch != _matched:
                                for _source in _cidrmatch[u'sources']:
                                    _cidrmatch[u'sources'][_source][u'query_type'] = _cidr
                                    if not _source in _result[u'sources']:
                                        _result[u'sources'][_source] = _cidrmatch[u'sources'][_source]
                                        _result[u'count'] += 1
                # retrieve matched record count
                if not _result[u'count']:
                    del _result[u'sources']
        except Exception as err:
            import traceback
            traceback.print_exc()
            
        #    _errmsg = templates.ERROR_GENERIC.format(
        #                    u'_query:_query_internal_bl',
        #                    type(err).__name__,
        #                    str(err))
        #    Logger(__meta__[u'shortname'], u'_query:_query_internal_bl',
        #            _errmsg, err, self.unattended, self.errors_out)
        #    pass
        return utilities.object_to_string(_result, self.json_out)

    def _query_match_convert(self, qtype, match):
        """ Converts match dictionary to output format """
        try:
            del match[u'start']
        except KeyError:
            pass
        try:
            del match[u'end']
        except KeyError:
            pass
        _record = {u'type': qtype}
        for _key in match:
            if _key != u'sources':
                _record[_key.title()] = match[_key]
            else:
                for _source in match[u'sources']:
                    _record[_source] = {}
                    for _key in match[u'sources'][_source]:
                        _record[_source][_key] = match[u'sources'][_source][_key]
        return _record

    def _retrieve_data(self, url):
        """ retrieve block list from data source """
        _data = None
        # create "Request" object to source
        _request = None
        _errmsg = None
        # construct request headers
        _reqhdrs = {u'User-Agent': utilities.USER_AGENT,
                    u'Accept': 'text/plain'}  # KEEP THIS?????
        _request = urlrequest.Request(url)
        for _header in _reqhdrs:
            _request.add_header(_header, _reqhdrs[_header])
        _request.method = u'GET'
        # retrieve new data file
        # connect to source and retrieve desired content
        try:
            with urlrequest.urlopen(_request) as _response:
                _status = _response.status
                if _status == 200:
                    # read in response content
                    _data = _response.read()
                    try:
                        _data = _data.decode(u'utf-8')
                    except:
                        pass
        except urllib.error.HTTPError as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_retrieve_data',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'_retrieve_data', _errmsg, self.unattended)
        except urllib.error.URLError as err:
            _errmsg = templates.ERROR_GENERIC.format(u'_retrieve_data',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'_retrieve_data', _errmsg, self.unattended)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'retrieve_data',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'_retrieve_data', _errmsg, self.unattended)
        return _data

    def _update_data_store(self, source_data,
                            source_name,
                            field_index=0,
                            delimiter=u',',
                            quotechar=u'"',
                            data_index=None,
                            data_delimiter=None,
                            list_type=u'block list'):
        """ update the data store with source data """
        # iterate through data
        _srccount = 0
        try:
            with StringIO(source_data) as _input:
                _reader = CSVReader(_input,
                                    delimiter=delimiter,
                                    quotechar=quotechar)
                for _row in _reader:
                    if not _row or _row[0].strip().startswith(u'#'):
                        continue
                    _newline = _row[field_index].strip()
                    if data_index > -1:
                        _parts = _newline.split(data_delimiter)
                        _newline = _parts[data_index].strip()
                        if not _newline:
                            continue
                    #determine type of value being added to block list
                    #_qtype = self._determine_qtype(_newline)
                    _qtype = utilities.determine_query_type(_newline)
                    if not _qtype:
                        _error = ValueError(u'The query type for the '\
                                            u'provided input value "{0}" '\
                                            u'from source "{1}" could '\
                                            u'not be determined.'.format(_newline,
                                                                        source_name))
                        Logger(__meta__[u'shortname'], u'_update_data_store', None,
                                _error, self.unattended)
                        continue
                    if self._add_to_store(qtype=_qtype,
                                            value=_newline,
                                            source=source_name,
                                            list_type=list_type):
                        _srccount += 1
                    else:
                        continue
        except Exception as err:
            import traceback
            traceback.print_exc()
        #    
        #    _errmsg = templates.ERROR_GENERIC.format(
        #                                    u'_update_data_store',
        #                                        type(err).__name__,
        #                                        str(err))
        #    Logger(__meta__[u'shortname'], u'_update_data_store', _errmsg,
        #            err, self.unattended)
        #    raise ProcessingError(err, _errmsg)
        # return the number of records added/updated
        return _srccount

    def cleanup(self):
        _deletecount = 0
        _maxage = -1
        _input = u''
        _qrytypes = [x.lower() for x in self.data_store.keys()]
        _qrytypes.append(u'all')
        _qryextended = [u'exit']
        _qryextended.extend(_qrytypes)
        _recordtype = u''
        while _recordtype not in _qryextended:
            _msg = u'Please enter one of the available record types '\
                    u'{0}. Enter "EXIT" to abort session: '.format([x.upper() for x in _qrytypes])
            _recordtype = utilities.standard_out(_msg, True).strip().lower()
        if _recordtype == u'exit':
            _msg = u'Aborting block list database cleanup...'
            utilities.standard_out(_msg, False)
        else:
            _msg = u'Record type: "{0}" selected. Continuing...'.format(_recordtype)
            utilities.standard_out(_msg, False)
            while _maxage < 0:
                _msg = u'Please enter the maximum age of a '\
                        u'block list source record (in number of days).\n'\
                        u'Any source record with an older "last_seen" '\
                        u'date will be removed.\nEnter "0" '\
                        u'to exit: '
                try:
                    _maxage = abs(int(utilities.standard_out(_msg, True)))
                except:
                    _maxage = -1
            if _maxage == 0:
                _msg = u'Aborting block list database cleanup...'
                utilities.standard_out(_msg, False)
            else:
                _input = u''
                while _input not in utilities.YESNO:
                    _msg = u'This action will remove the source record for any '\
                            u'block list value whose\n"last_seen" field is over '\
                            u'{0} days old. Continue? [Y|N]: '.format(_maxage)
                    _input = utilities.standard_out(_msg, True).strip()[0].upper()
                if _input == u'Y':
                    for _qtype in self.data_store:
                        if _recordtype != u'ALL' and not _qtype == _recordtype:
                            continue
                        for _value in self.data_store[_qtype]:
                            for _source in self.data_store[_qtype][_value][u'sources']:
                                _lastseen = self.data_store[_qtype][_value][u'sources'][_source][u'last_seen']
                                _currentdate = datetime.today()
                                _dateparts = _lastseen.split(u'-')
                                _lastseendate = datetime(int(_dateparts[0]),
                                                int(_dateparts[1]), int(_dateparts[2]),
                                                _currentdate.hour,
                                                _currentdate.minute,
                                                _currentdate.second,
                                                0)
                                _currentage = _currentdate - _lastseendate
                                if  _currentage.days > _maxage:
                                    # set delete flag
                                    self.data_store[_qtype][_value][u'sources'][_source][u'delete'] = True
                                    _deletecount += 1
                    if _deletecount:
                        _input = u''
                        while _input not in utilities.YESNO:
                            _msg = u'This action will remove {0} records from the '\
                                    u'internal block list database\nand may not be '\
                                    u'aborted once begun. Continue? [Y|N]: '.format(_deletecount)
                            _input = utilities.standard_out(_msg, True).strip()[0].upper()
                        if _input == u'Y':
                            for _qtype in self.data_store:
                                if not _recordtype == u'all' and not _qtype == _recordtype:
                                    continue
                                for _value in self.data_store[_qtype]:
                                    for _source in self.data_store[_qtype][_value][u'sources']:
                                        try:
                                            if self.data_store[_qtype][_value][u'sources'][_source][u'delete']:
                                                # remove the source specific value record
                                                del self.data_store[_qtype][_value][u'sources'][_source]
                                        except KeyError:
                                            pass
                        else:
                            _deletecount = 0
                            _msg = u'Aborting block list database cleanup...'
                            utilities.standard_out(_msg, False)
                            _msg = u'Removing block list record "delete" flags...'
                            utilities.standard_out(_msg, False)
                            for _qtype in self.data_store:
                                if not _recordtype == u'all' and not _qtype == _recordtype:
                                    continue
                                for _value in self.data_store[_qtype]:
                                    for _source in self.data_store[_qtype][_value][u'sources']:
                                        try:
                                            self.data_store[_qtype][_value][u'sources'][_source][u'delete'] = False
                                        except KeyError:
                                            pass
                    else:
                        _msg = u'No matching records found. Exiting...'
                        utilities.standard_out(_msg, False)
                else:
                    _msg = u'Aborting block list database cleanup...'
                    utilities.standard_out(_msg, False)
        return u'Number of block list records deleted: {0}'.format(_deletecount)

    def count(self):
        """ return the count of records for each stored record type """
        _result = u'{0}: {1}\n'.format(u'query_datetime',
                                str(datetime.today()).split(u'.')[0])
        for _qtype in self.data_store:
            _result += u'{0}: {1}\n'.format(_qtype,
                                    str(len(self.data_store[_qtype])))
        return _result

    def query(self):
        """ execute a query against the internal blocklist """
        _success = False
        _update = self.verify_bl_update()
        if _update:
            _input = u''
            while _input not in utilities.YESNO:
                _msg = u'The internal blocklist database has not been '\
                            u'updated today. Update now? '\
                            u'[Y|N] :'
                _input = utilities.standard_out(_msg, True).strip()[0].upper()
            if _input == u'Y':
                if not self.unattended:
                    _msg = u'Updating block list entries...'
                    utilities.standard_out(_msg)
                self.update()
            else:
                _msg = u'Skipping block list update...'
                utilities.standard_out(_msg)
        # begin querying of provided query string(s)
        _results = self._query()
        # if result is string and an existing file
        if not _results:
            _msg = u'NO RESULTS:The submitted query did '\
                        u'not identify any results matching\n '\
                        u' the provided parameters.\n\n'
            utilities.standard_out(_msg)
        #convert results to string output based on output_type
        _content = u''
        if self.output_type in [u'csv', u'html']:
            _rows = self._convert_to_rows(_results)
            if self.output_type == u'csv':
                for _row in _rows:
                    _next = u'","'.join(_row)
                    _content += u'"{0}"\n'.format(_next)
            elif self.output_type == u'html':
                _content = self._convert_to_html(_rows)
        elif self.output_type == u'json':
            _content = json.dumps(_result, indent=2)
        else: # assume output to console
            _content = _results
        # persist content of send to terminal window
        _output = None
        try:
            if type(_content) is str:
                # persist content to file and return filepath
                _filepath = self._persist_content(_content)
                _output = _filepath
                _success = True
            else:
                #return the results dictionary object
                _filepath = None
                _output = u'{0}\n'.format(utilities.result_to_string(_results))
                _success = True
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(u'query',
                                                type(err).__name__,
                                                str(err))
            Logger(__meta__[u'shortname'], u'query', _errmsg, self.unattended)
            pass
        if _success:
            if _filepath and os.path.exists(_filepath):
                # open results file in appropriate applcation
                # suppress resource warnings
                filterwarnings(action="ignore")
                # let user know where logical file was created
                _msg = u'Query results saved to: '\
                                    u'{0}\n'.format(_filepath)
                utilities.standard_out(_msg)
                # open corresponding application for content display
                if system() == 'Darwin':       # macOS
                    call([u'open', _filepath],
                            stdout=DEVNULL,
                            stderr=DEVNULL)
                elif system() == 'Windows':    # Windows
                    os.startfile(_filepath)
                else:                           # linux variants
                    call([u'xdg-open', _filepath],
                            stdout=DEVNULL,
                            stderr=DEVNULL)
            else:
                # return results to terminal window
                utilities.standard_out(_output)
            _success = True
        else:  # what is this? Hmm...
            _errmsg = u'The format of the returned value '\
                        u'is not recognized.\nOutput: {0}'.format(
                                                    str(_results))
            raise ValueError(_errmsg)
        return _success

    def update(self):
        """
            iterates through defined IP sources and
            updates information in stored list
        """
        _updated = 0
        # check if daily update has already been done, or "override"
        if self.unattended or self.override:
            # perform list update
            _update = True
        else:  # check date of last update
            _updated = self.verify_bl_update()
        if _updated:
            if not self.unattended:
                _msg = u'Today\'s update of the Block List Manager '\
                            u'data store has already been performed.'
                utilities.standard_out(_msg)
                _input = u''
                while _input not in utilities.YESNO:
                    _msg = u'Override the once daily update constraint, '\
                                    u'if necessary? [Y|N] '
                    _input = utilities.standard_out(_msg, True).strip()[0].upper()
                if _input == 'Y':
                    _updated = False
        if not _updated:
            if not self.unattended:
                _msg = u'Updating the Block List Manager from defined sources now...\n'
                utilities.standard_out(_msg)
            # save last run date to file
            with open(self.lastupdatepath, 'wt') as f_out:
                f_out.write(str(datetime.today()).split(u' ')[0])
            if not self.unattended:
                _msg = u'Retrieving updates from data sources...'
                utilities.standard_out(_msg)
            # begin data store update
            try:
                for _source in self.config:
                    _srccount = 0
                    # insure that it is a source url provided
                    if u'source' not in self.config[_source]:
                        continue
                    # make sure source is "active"
                    if not self.config[_source][u'active'].lower() == u'true':
                        continue
                    _url = self.config[_source][u'source']
                    _listtype = self.config[_source][u'list_type']
                    _fldndx = 0
                    try:
                        _fldndx = int(self.config[_source][u'field_index'])
                    except ValueError:
                        pass
                    _fldsep = self.config[_source][u'field_separator']
                    _datndx = -1
                    try:
                        _datndx = int(self.config[_source][u'data_index'])
                    except ValueError:
                        pass
                    _datsep = self.config[_source][u'data_separator']
                    if not self.unattended:
                        _msg = u'Retrieving source: {0}...'.format(_source)
                        utilities.standard_out(_msg)
                    # retrieve data
                    _data = self._retrieve_data(_url)
                    if not _data:
                        continue                        
                    if not self.unattended:
                        _msg = u'Updating data store...'
                        utilities.standard_out(_msg)
                    # add/update information in data store from source
                    _srccount = self._update_data_store(source_data=_data,
                                                        source_name=_source,
                                                        field_index=_fldndx,
                                                        delimiter=_fldsep,
                                                        quotechar=u'"',
                                                        data_index=_datndx,
                                                        data_delimiter=_datsep,
                                                        list_type=_listtype)
                    if not self.unattended:
                        _msg = u'{0} records add/updated from '\
                                        u'Source: {1}\n'.format(_srccount,
                                        _source.title())
                        utilities.standard_out(_msg)
                    _updated += _srccount
                    if _srccount:
                        # persist changes to file after each source
                        try:
                            self._persist_store()
                        except Exception as err:
                            raise err
            except ProcessingError as err:
                import traceback
                traceback.print_exc()
            #    raise err
            #except Exception as err:
            #    raise ProcessingError(err)
        # create message for updates log
        _msg = u'Update completed. {0} additions/updates'.format(_updated)
        Logger(__meta__[u'shortname'], u'update', None, _msg, self.unattended)
        # return the counts of values processed
        return {u'Additions/Updates': _updated}

    def verify_bl_update(self):
        """ check if daily update has already been done """
        _update = True
        _lastrun = None
        if os.path.exists(self.lastupdatepath):
            with open(self.lastupdatepath, 'rt') as f_in:
                _lastrun = f_in.read()
        if _lastrun:
            if (self.today <= str(_lastrun).split(u' ')[0] and
                not self.override):
                    _update = False
        return _update


if __name__ == '__main__':

    from argparse import ArgumentParser
    # instantiate argument parser
    _parser = ArgumentParser(description=u'Block list retrieval, '\
                                            u'update and querying tool')
    _parser.add_argument(u'-a', '--action', default=u'query',
                            choices=[u'cleanup', u'count', u'query',
                                        u'update',u'whois'],
                            help='The type of action you would like to '\
                            u'execute with Block List Manager. '\
                            u'(DEFAULT: query)')
    _parser.add_argument(u'-q', '--query', default=u'',
                            help='The value to be queried against the '\
                            u'data store. Supports IPv4 & IPv6 addresses, '\
                            u'as well as CIDRv4 and CIDRv6 network ranges. '\
                            u'This parameter must be used in combination '\
                            u'with the "-a query" parameter.')
    _parser.add_argument(u'-f', '--filepath', default=u'',
                            help='The path to an file containing a line '\
                            u'separated list of IP addess/CIDR values to '\
                            u'query. This parameter must be used in '\
                            u'combination with the "-a query" parameter.')
    _parser.add_argument(u'-o', u'--output_type', type=str, default='html',
                            choices=[u'csv', u'html', u'json'],
                            help='Output results in designated format '\
                            u'(html|json|tab) (DEFAULT: json)')
    _parser.add_argument('--config_file', default=u'',
                            help='Path to the Block List Manager '
                            u'configuration file. If not provided, '\
                            u'the application defaults to file: '\
                            u'<app_path>/config/blmanager.cfg. '\
                            u'Use of default config file is recommended.')
    _parser.add_argument(u'--unattended', type=str, default='False',
                            choices=[u'True', u'False'],
                            help='Application is running without user '\
                            u'input, e.g. cron job (DEFAULT: False) '\
                            u'Note: Setting value to "True" will also '\
                            u'set --override to "True".')
    _parser.add_argument(u'--override', type=str, default='False',
                            choices=[u'True', u'False'],
                            help='Override the once daily update '\
                            u'constraint (DEFAULT: False)')
    _parser.add_argument(u'--raw', type=str, default=u'',
                            choices=[u'ipv4', u'ipv6', u'cidrv4', u'cidrv6'],
                            help='Output all records in the data store '\
                            u'for the indicated record type as '\
                            u'a JSON-formatted string. (DEFAULT: null)')
    # parse out command line arguments
    _args = _parser.parse_args()

    if (not _args.raw and _args.action in [u'query', u'whois'] and
        (not _args.query and not _args.filepath)):
        sys.exit(u'ERROR: A "query" string value (parameter "-q") or '\
                    u'a file path (parameter "-f") must be provided to '\
                    u'execute a block list or whois query.\n')
    _unattended = False
    if _args.unattended == u'True':
        _unattended = True
    _override = False
    if (_args.override == u'True' or
        _unattended):
        _override = True
    #_jsonout = False
    #if _args.json == u'True':
    #    _jsonout = True
    _result = None
    # instantiate Block List Manager object instance
    _blmanager = BLManager(config=_args.config_file,
                            query=_args.query,
                            list_path=_args.filepath,
                            output=_args.output_type,
                            unattended=_unattended,
                            override=_override)
    # handle any requests for "raw" data first
    if _args.raw:
        # this parameter outputs ALL content for the indicated
        # record type in formatted json
        _errmsg = u''
        try:
            print(json.dumps(_blmanager.data_store[_args.raw], indent=2))
        except KeyError:
            _errmsg = u'The indicated data type: {0} is not recognized, '\
                        u'or does not exist in the data store. Please '\
                        u'try again.\n'.format(_args.raw)
            pass
        except Exception as err:
            _errmsg = u'{0}\n'.format(str(err))
            pass
        sys.exit(_errmsg)
    else:
        _action = _args.action.lower()
        if _action == u'query':
            # output is handled within the query procedure
            _result = _blmanager.query()
            pass
        elif _action == u'whois':
            _result = utilities.retrieve_whois(_args.query.lower())
        elif _action == u'update':
            _result = _blmanager.update()
        elif _action == u'count':
            _result = _blmanager.count()
        elif _action == u'cleanup':
            _result = _blmanager.cleanup()
        else:
            sys.exit(u'The requested action: "(0) is not recognized. '\
                        u'Exiting...\n'.format(_rgs.action))
    # output the results to terminal window
    _type = type(_result)
    if _type is bool:
        pass
    elif _type is dict:
        for _item in _result:
            print(utilities.result_to_str(_result[_item], _item))
    elif _type is str:
        print(_result)
    else:
        sys.stdout.write(u'No results found for indicated action.\n')
