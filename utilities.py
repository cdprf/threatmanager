#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import json
import os
import re
import sys
import templates
import urllib
from configparser import ConfigParser
from contextlib import redirect_stdout
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from datetime import datetime

import utilities
from templates import ERROR_GENERIC, ABUSE_IP_QUERY, VT_IP_QUERY
from time import time
from urllib import request as urlrequest
from urllib.parse import urlencode
from urllib.error import HTTPError
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
    import pydnsbl
except:
    sys.exit(templates.LOAD_ERROR.format(u'pydnsbl',
                            u'https://pypi.org/project/pydnsbl/',
                            ))
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

    File Name:      utilities.py
    Created:        June 6, 2022
    Author:         <dmranta>[@]<cert.org>

    Description:    Utility functions, regular expressions, constants,
                    etc., supporting IntelManager object functionality
#######################################################################
"""

""" Versioning
#######################################################################

    2022-06-12  Ver 0.1 Initial release
    2022-06-14  Ver 0.2 Added CIDR range count parameter to stored
                        CIDR ranges
    2022-07-05  Ver 1.0 Implemented within Threat Manager suite
    2022-07-13  Ver 1.1 Missing API key handling to no longer prompt
                        for keys.
                        Removed "retrieve_internal_blocklist" function
                        Added "remove_legacy_results" function
                        Added "retrieve_greynoise" function
    2022-07-14  Ver 1.2 Corrected error handling for missing API key
    2022-09-27  Ver 1.3 Changes to GreyNoise request error handling
#######################################################################
"""


__meta__ = {u'title': u'Threat Manager Utilities',
            u'longname': u'Threat Manager Utilities',
            u'shortname': u'utilities',
            u'version': u'1.3',
            u'author': u'Donald M. Ranta Jr.',
            u'copyright':u'Software Engineering Institute @ '\
                            u'Carnegie Mellon University'}
# path to application execution directory
APP_PATH = os.path.abspath(os.path.dirname(__file__))
# Date input regular expression
REGEX_DATE = re.compile(r'^\d{4}(\-|\/)\d{2}(\-|\/)\d{2}$')
# Domain name verification regex
REGEX_DOMAIN = re.compile(r'(^([a-z][-a-z0-9]*\.)(([-a-z0-9]+\.)+)?'\
                            r'(([a-z]{2,16})|(xn--[a-z]{2-16}))$)', re.I)
# used for input content validation
QUERY_RGXS = {u'hostname': re.compile(r'^([a-z0-9]+(\-)*[a-z0-9]*\.)'\
                            r'+[a-z]{2,24}$'),  
                u'net': re.compile(r'^((((25[0-5])|(2[0-4][0-9])|(1[0-9][0-9])|'\
                            r'([1-9][0-9])|[0-9])\.){3}((25[0-5])|'\
                            r'(2[0-4][0-9])|(1[0-9][0-9])|([1-9][0-9])|'\
                            r'[0-9])(\/((3[0-2])|([12][0-9])|[0-9]))?)$'),
                u'ipv6':re.compile(r'^(([a-f0-9]{1,4}:)+|:)+([a-f0-9]{1,4})?$', re.I)}
# define constant values
USER_AGENT = u'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '\
                u'(KHTML, like Gecko) Chrome/99.0.4844.51 '\
                u'Safari/537.36'
# yes/no options
YESNO = [u'Y', u'N']
# API key sources
API_SOURCES = [u'abuseip', u'nistnvd', u'shodan',
                        u'securitytrails', u'virustotal']
# IP registrues and lookup links
ASN_REGISTRY_LINKS = {u'afrinic': u'https://rdap.afrinic.net/rdap/ip/{0}',
                        u'arin': u'https://search.arin.net/rdap/?query={0}',
                        u'apnic': u'https://wq.apnic.net/static/search.html?query={0}',
                        u'lacnic': u'https://query.milacnic.lacnic.net/search?id={0}',
                        u'ripencc': u'https://apps.db.ripe.net/db-web-ui/query?searchtext={0}'}

# Common exception for use with Threat manager
class ProcessingError(Exception):
    """ defines basic exception to return """
    def __init__(self, err, error_msg=None):
        if error_msg:
            self.error_message = error_msg
        else:
            self.error_message = u'{0}-{1}'.format(type(err).__name__,
                                                    str(err))

    def __str__(self):
        return self.error_message

def cidr_to_iprange(cidr_address, minmax=False, short_name=u''):
    """ convert CIDR to individual IP addresses """
    _range = []
    _addr = str(cidr_address)
    try:
        _version = ip_network(_addr).version
        if _version == 4:
            _range = [str(_ip) for _ip in IPv4Network(cidr_address)]
            _count = len(_range)
            if minmax:
                _range = (int(IPv4Address(_range[0])),
                            int(IPv4Address(_range[1])),
                            _count)
        if _version == 6:
            _range = [str(_ip) for _ip in IPv6Network(cidr_address)]
            _count = len(_range)
            if minmax:
                _range = (int(IPv6Address(_range[0])),
                            int(IPv6Address(_range[1])),
                            _count)
    except Exception as err:
        _errmsg = ERROR_GENERIC.format(u'cidr_to_iprange',
                                        type(err).__name__,
                                        str(err))
        logger(short_name, 'cidr_to_iprange', _errmsg, err)
    return _range

def convert_to_json(dict_object):
    """ convert python object to JSON with default error handler """
    return json.dumps(dict_object, indent=2,
                        default=json_val2str)

def create_header_row(title, value):
    """ takes input and outputs header row for html output """
    _header = u'<b>{0}:</b> {1}'.format(
                                    title.title().replace(u'_', u' '),
                                    value)
    return _header

def create_table_header(field_names):
    """use list of fieldnames to create HTML table header"""
    _headertemplate = u'<th title="Sort by {0}" onclick="sortTable({1});">{0}</th>'
    _columns = []
    _count = 0
    for _fieldname in field_names:
        _columns.append(_headertemplate.format(
                            _fieldname.replace(u'_',u' ').upper(),
                                                _count))
        _count += 1
    _header = u'<tr>\n{0}</tr>\n'.format(u''.join(_columns))
    # return the formatted html table header
    return _header

def create_table_row(field_values):
    """use list of field valuess to create HTML table <td> row """
    _fieldtemplate = u'<td>{0}</td>'
    _fields = []
    _count = 0
    for _value in field_values:
        _nextval = u''
        if _value:
            _type = type(_value)
            if _type is list:
                _nextval = u' '.join([x for x in _value if x])
            else:
                _nextval = str(_value).replace(u'\n', u'<br>')

        _fields.append(_fieldtemplate.format(_nextval))
        _count += 1
    _row = u'<tr>\n{0}</tr>\n'.format(u''.join(_fields))
    # return the formatted html table row
    return _row

def create_csv_content(records):
    """ takes list of python dictionaries and converts to row format """
    _rows = []
    _rowtemplate = "{0}"
    _delimiter = '","'
    # iterate through records adding rows
    for _record in records:
        _newrow = []
        for _field in _record:
            _value = _field
            if type(_value) is list:
                _value = u' '.join(_value)
            _value = str(_value).replace(u'"', u'\\"')
            _newrow.append(_value)
        _rows.append(_rowtemplate.format(_delimiter.join(_newrow)))
    # return all rows converted to a newline delimited string
    return u'\n'.join(_rows)

def day_of_week():
    """ returns 3 character day of week """
    _weekday = datetime.now().isoweekday()
    if _weekday == 1:
        _weekday = u'Mon'
    elif _weekday == 2:
        _weekday = u'Tue'
    elif _weekday == 3:
        _weekday = u'Wed'
    elif _weekday == 4:
        _weekday = u'Thu'
    elif _weekday == 5:
        _weekday = u'Fri'
    elif _weekday == 6:
        _weekday = u'Sat'
    elif _weekday == 7:
        _weekday = u'Sun'
    return _weekday

def determine_query_type(query):
    """ determines the format of submitted data """
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
        _errmsg = templates.ERROR_GENERIC.format(u'determine_query_type',
                                        type(err).__name__,
                                        str(err))
        logger(__meta__[u'shortname'], u'determine_query_type', _errmsg,
                err, True)
        pass
    return _qtype
        
def json_val2str(dict_obj):
    """ converts object value to json serializable format """
    _newval = None
    try:
        if isinstance(dict_obj, datetime):
            _newval = dict_obj.isoformat()
        else:
            _newval = dict_obj.__str__()
    except:
        pass
    return _newval

def load_api_info(api_config_path,  # full path to the api config file
                    api_required,  # a single required  API cources
                    api_optional): #,  # a list of optional API sources
    """ loads necessary required and optional API information from file """
    _apiinfo = {}
    try:
        _apirequired = api_required.strip().lower()
        _apioptional = [x.strip().lower().replace(u' ', u'')
                        for x in api_optional if x.strip()]
        if (os.path.exists(api_config_path) and
            os.access(api_config_path, os.R_OK)):
            _cfparser = ConfigParser()
            _cfparser.read(api_config_path)
            _errmsg = u''
            if _apirequired:
                if _apirequired not in _cfparser:
                    _errmsg = u'The required API source: {0} is not '\
                    u'provided in the configuration file "{1}"'\
                    u''.format(_apirequired, api_config_path)
                elif (u'active' in _cfparser[_apirequired] and
                    not _cfparser[_apirequired][u'active'].lower()==u'true'):
                    _errmsg = u'The required API source: {0} '\
                    u'is marked as "Inactive" in the configuration '\
                    u'file: {1}.'.format(_apirequired, api_config_path)
                elif u'apikey' not in _cfparser[_apirequired]:
                    _errmsg = u'The required API source: {0} is missing '\
                    u'the "apikey" field.'.format(_apirequired)
                elif not _cfparser[_apirequired][u'apikey']:
                    _errmsg = u'The required API source: {0} '\
                    u'is missing a value for the "apikey" '\
                    u'field.'.format(_apirequired)
                if _errmsg:
                    raise ValueError(_errmsg)
                else:
                    _apiinfo[_apirequired] = {u'apikey':
                                            _cfparser[_apirequired][u'apikey']}
            # iterate through optional API sources
            for _section in _apioptional:
                _active = False
                if _section in _cfparser:
                    try:
                        _active = _cfparser[_section][u'active'].lower().strip()
                        if _active == u'true':
                            _active = True
                        else:
                            _active = False
                    except KeyError:
                        pass
                    if _active:
                        _newkey = None
                        try:
                            _newkey = _cfparser[_section][u'apikey'].strip()
                        except KeyError:
                            pass
                        if _newkey:
                            _apiinfo[_section] = {u'apikey': _newkey}
                        else:
                            _msg = u'The optional API key  for '\
                                u'source: {0} is missing. Source '\
                                u'content will not be available.'\
                                u'Skipping...'.format(_section.upper())
                            standard_out(_msg, False)
                            try:
                                del _apiinfo[_section]
                            except:
                                pass
                    else:
                        _msg = u'The optional API source: {0} '\
                                u'is marked as "Inactive", or does not '\
                                u'have the "active" field set, in the '\
                                u'configuration file: {1}. Skipping...'\
                                u''.format(_section.upper(), api_config_path)
                        standard_out(_msg, False)
                else:  # missing required fields, continuing                    
                    _msg = u'-->The optional API source: {0} is '\
                    u'missing one or more required fields. '\
                    u'Skipping...\n'.format(_section.upper())
                    standard_out(_msg, False)
    except Exception as err:
        raise err
    return _apiinfo

def logger(application, method, message,
            err=None, unattended=False, errors_out=True):
    """ common Threat Manager logging method """
    _apppath = os.path.abspath(os.path.dirname(__file__))
    _recorddt = datetime.now().isoformat()
    _errmsg = message
    if err:
        _errorname = type(err).__name__
        _logname = u'Error'
        _err_entry = u'"{0}","{1}","{2}","{3}"\n'.format(
                                        _recorddt,
                                        method,
                                        _errorname,
                                        message)
    else:
        _logname = u'Process'
        _err_entry = u'"{0}","{1}","{2}"\n'.format(
                                         _recorddt,
                                        method,
                                        message)
    # write errors to terminal if indicated
    if not unattended and errors_out:
        standard_out(u'{0}: {1}\n'.format(_recorddt,message))
    try:
        # construct path to log file
        _logspath = os.path.join(_apppath, u'logs', application)
        if not os.path.exists(_logspath):
            os.makedirs(_logspath)
        _filepath = os.path.join(_logspath, u'{0}_{1}_{2}.log'.format(
                                                        _logname,
                                                        application,
                                                        day_of_week()))
        _now = time()
        if (not os.path.exists(_filepath) or
            (_now - os.path.getmtime(_filepath))< 86400.0):
            with open(_filepath, 'a') as f_out:
                f_out.write(_err_entry)
        else:
            with open(_filepath, 'w') as f_out:
                f_out.write(_err_entry)
    except Exception as err:
        errmsg = u'Exception: {1} occurred. '\
                        u'Message: {2}'.format(type(err).__name__,
                                                str(err))
        standard_out(u'Logging Error: {0}\n'.format(_errmsg))

def object_to_string(input_object, json_out=False):
    _outputstring = u''
    _template = u'{0}\n'
    _objtype = type(input_object)
    if _objtype in [str, int, float, bool]:
        _outputstring += str(input_object)
    elif _objtype is list:
        for _entry in input_object:
            _outputstring += _template.format(object_to_string(_entry))
    elif _objtype is dict:
        for _key in input_object:
            _type = type(input_object[_key])
            if _type in [bool,float,int, str]:
                _outputstring += u'{0}: {1}\n'.format(_key,
                                    str(input_object[_key]))
            elif _type is list and input_object[_key]:
                _outputstring += u'{0}: {1}\n'.format(_key,
                                    u'|'.join(input_object[_key]))
            elif _type is dict and input_object[_key]:                
                _outputstring += u'{0}:\n{1}\n'.format(_key,
                                    object_to_string(input_object[_key]))
                        
    return _outputstring

def remove_legacy_results(max_age=30):
    """ removes legacy results based on age of file"""
    _resultsdir = os.path.join(APP_PATH, u'results')
    _subdirs = [x for x in os.listdir(_resultsdir)
            if os.path.isdir(os.path.join(_resultsdir, x))]
    _subdirs.append(u'exit')
    _input = u''
    while _input not in _subdirs:
        _msg = u'Please enter the results directory to inspect.\n'\
                u'Options include [{0}]. Use "exit" to abort. '\
                u''.format(u'|'.join(_subdirs))
        _input = standard_out(_msg, True)
    if _input != u'exit':
        _targetdir = os.path.join(_resultsdir, _input)
        _maxage = -1
        while _maxage < 0:
            _msg = u'Please enter the maximum age of files to be '\
                    u'retained (in days).\nEnter "0" to use the '\
                    u' 30 day default. '
            try:
                _maxage = int(standard_out(_msg, True).strip())
            except:
                pass
        if _maxage == 0:
            _maxage = max_age
        _msg = u'Removing files from directory: {0}'.format(_targetdir)
        standard_out(_msg)
        _msg = u'Maximum file age: {0} days'.format(_maxage)
        standard_out(_msg)
        #retrieve current datetime
        _now = datetime.now()
        _delcount = 0
        for _file in os.listdir(_targetdir):
            _targetfile = os.path.join(_targetdir, _file)
            if os.path.isfile(_targetfile):
                _mtime = datetime.fromtimestamp(os.path.getmtime(_targetfile))
                _delta = (_now-_mtime).days
                if _delta > _maxage:
                    _msg = u'File: {0} is {1} days old. Removing...'\
                            u''.format(_file, _delta)
                    standard_out(_msg)
                    try:
                        os.remove(_targetfile)
                        _delcount += 1
                    except:
                        raise
        _msg = u'File removal has completed.'
        standard_out(_msg)
        _msg = u'Number of file removed: {0}'.format(_delcount)
        standard_out(_msg)
    else:
        _msg = u'Process aborted by user. Exiting...'
        standard_out(_msg)

def result_to_str(obj, key=None):
    """ iterates through python object hierarchy and converts to string output """
    _outputstring = u''
    _hdrtemplate = u'{0}\n'
    _entrytemplate = u'{0}{1}: {2}\n'
    _collection = []
    _type = type(obj)
    if not obj and key:
       _outputstring += _entrytemplate.format(u'', key.upper(), u'No Result')
    elif _type is str:
        if key:
            _outputstring += _entrytemplate.format(u'',key.lower(), obj)
        else:
            _outputstring += _hdrtemplate.format(obj.upper())
    elif _type is dict:
        if key:
            _outputstring += _hdrtemplate.format(key.upper())
        for _key in obj:
           _outputstring += result_to_str(obj[_key], _key.lower())
    elif _type is list:
        if key:
            _outputstring += _hdrtemplate.format(key.upper())
        for _entry in obj:
            _outputstring += result_to_str(_entry)
    return _outputstring

def result_to_string(result):
    _outstr = u'Block List Query Results\n{0}\n'.format(u'='*25)
    _entrytmpl = u'{0}: {1}\n'
    for _key in result:
        if _key != u'results':
            _outstr += _entrytmpl.format(
                        _key.replace(u'_', u' ').strip().lower()(),
                        result[_key])
        else:  # iterate through results list
            if not result[_key]:
                _outstr += _entrytmpl.format(u'Results', u'None')
            else:
                _outstr += u'\nResults\n{0}\n'.format(u'='*7)
                for _entry in result[_key]:
                    for _dictkey in _entry:
                        if type(_entry[_dictkey]) is not dict:
                            _value = _entry[_dictkey]
                            if not _value:
                                _value = u'None'
                            _outstr += _entrytmpl.format(_dictkey.replace(u'_', u' '),
                                                    _entry[_dictkey])

                        else: # its a dictionary
                            _outstr += _entrytmpl.format(u'Source',
                                                            _dictkey)
                            for _subkey in _entry[_dictkey]:
                                _value = _entry[_dictkey][_subkey]
                                if not _value:
                                    _value = u'None'
                                _outstr += _entrytmpl.format(_subkey.replace(u'_', u' ').title(),
                                                                _value)
                            _outstr += u'\n'
                _outstr += u'\n'
    return _outstr

def retrieve_AbuseIPDB(addresses, api_key=None, json_out=False,
                        unattended=False, max_age=90):
    """
        retrieve information from AbuseIPDB for those IPs that have been
        reported one or more times for abuse in the past "maxage" (90) days
    """
    _method = u'retrieve_AbuseIPDB'
    _data = None
    _output = u'No Match'
    _qryurl = u'https://api.abuseipdb.com/api/v2/check?ipAddress={0}&maxAgeInDays={1}'
    _request = None
    if type(addresses) is str:
        _addresses = [addresses]
    elif type(addresses) is list:
        _addresses = addresses
    else:
        raise ValueError(u'The "addresses" parameter must be either a '\
                            u'single IP address or a list of IP addresses.')
    _results = []
    #_collection = []
    if not api_key:
        _msg = u'An API key was not provided for AbuseIPDB. '\
                u'Lookups disabled.'
        utilities.standard_out(_msg, False)
        _output = u'Lookups Disabled'
    else:
        try:
            for _address in _addresses:
                _request = urlrequest.Request(_qryurl.format(_address, max_age))                
                _guiurl = u'https://www.abuseipdb.com/check/{0}'.format(_address)
                # construct request headers
                _reqhdrs = headers = {u'Accept': u'application/json',
                                        u'Key': api_key,
                                        u'User-Agent': USER_AGENT}
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
                            _data = json.loads(_response.read())
                except urllib.error.HTTPError as err:
                    _errmsg = u'AbuseIPDB: HTTP {1} - {2} '\
                                u''.format(_address, err.code, err.reason)
                    _data = {u'query': _address,
                                u'error': _errmsg}
                    logger(__meta__[u'shortname'], _method,
                                _errmsg, None, unattended)
                    pass
                except urllib.error.URLError as err:
                    _errmsg = u'AbuseIPDB: {0}'.format(err.reason)
                    logger(__meta__[u'shortname'], _method,
                                _errmsg, err, unattended)
                    pass
                except Exception as err:
                    _errmsg = templates.ERROR_GENERIC.format(
                                                    _method,
                                                    type(err).__name__,
                                                    str(err))
                    logger(__meta__[u'shortname'], _method, _errmsg, None,
                            unattended)
                    pass
                _dict = {}
                if _data and u'data' in _data and _data[u'data']:
                    for _key in _data[u'data']:
                        _dict[_key] = _data[u'data'][_key]
                    for _field in _dict:
                        if not _dict[_field]:
                            if _field.startswith(u'is'):
                                _dict[_field] = u'False'
                            else:
                                _dict[_field] = u'0'
                    _dict['link'] = u'<a href="{0}" target="_blank">AbuseIPDB'\
                                    u'</a>'.format(_guiurl)
                elif u'error' in _data:
                    _dict = _data
                _results.append(_dict)
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(
                                            _method,
                                            type(err).__name__,
                                            str(err))
            logger(__meta__[u'shortname'], _method, _errmsg, None,
                    unattended)
            _results = _errmsg
            pass
    _output_string = object_to_string(_results, json_out)
    #return output string
    return _output_string

def retrieve_DNSBL(addresses, json_out=False):
    """ queries multiple DNSBLs for presence of io address """
    _method = u'retrieve_DNSBL'
    _output_string = u''
    _results = []
    _collection = []
    if type(addresses) is str:
        _addresses = [addresses]
    elif type(addresses) is list:
        _addresses = addresses
    else:
        raise ValueError(u'The "addresses" parameter must be either a '\
                            u'single IP address or a list of IP addresses.')   
    for _address in _addresses:
        try:
            _data = None
            _qtype = determine_query_type(_address)
            if _qtype.startswith(u'ipv'):
                _checker = pydnsbl.DNSBLIpChecker()
            else: #assumes domain name
                _checker = pydnsbl.DNSBLDomainChecker()
            # retrieve results
            _output = u''
            _returned = _checker.check(_address)
            if _returned:
                _data = {u'blocklisted': str(_returned.blacklisted),
                        u'block_lists': [str(x) for x in _returned.detected_by.keys()],
                        u'categories': [x for x in _returned.categories],
                        u'query': _address,                
                        u'providers_queried': str(len([x for x in _returned.providers]))}
            if _data:
                _results.append(_data)        
        except Exception as err:
            _errmsg = templates.ERROR_GENERIC.format(
                                            _method,
                                            type(err).__name__,
                                            str(err))
            logger(__meta__[u'shortname'], _method, _errmsg, None)
            _results = _errmsg
            pass
    _output_string = object_to_string(_results, json_out)
    return _output_string

def retrieve_domain_ips(domain_name, dns_server=None, unattended=False):
    """ retrieves the ip addresses associated with a given domain name """
    _method = 'retrieve_domain_ips'
    _domain_ips = []
    _excluded_ips = cidr_to_iprange(u'172.16.0.0/12',
                                                False,
                                                __meta__[u'shortname'])
    try:
        if dns_server:
            _resolver = dnsresolver.Resolver(configure=False)
            _resolver.nameservers = [dns_server]
            _resolver.port = 53
        else:
            _resolver = dnsresolver.Resolver(configure=True)
        for _recordtype in [u'A', u'AAAA']:
            try:
                _dnsinfo = _resolver.resolve(domain_name, rdtype=_recordtype)
                if _dnsinfo:
                    for _item in _dnsinfo.rrset.items:
                        _ipstr = str(_item)
                        if (_ipstr.startswith(u'10.') or
                            _ipstr.startswith(u'192.168.') or
                            _ipstr.startswith(u'127.') or
                            _ipstr in _excluded_ips):
                            continue
                        else:
                            _domain_ips.append(_ipstr)
            except dnsresolver.NoAnswer as err:
                _errmsg = u'DNS ERROR: {0}'.format(str(err))
                logger(__meta__[u'shortname'], _method,
                        _errmsg, None, unattended)
                pass
            except dnsresolver.NXDOMAIN as err:
                _errmsg = u'DNS ERROR: {0}'.format(str(err))
                logger(__meta__[u'shortname'], _method,
                        _errmsg, None, unattended)
                pass
            except dnsresolver.NoNameservers as err:
                _errmsg = u'DNS ERROR: {0}'.format(str(err))
                logger(__meta__[u'shortname'], _method,
                        _errmsg, None, unattended)
                pass
            except dnsresolver.Timeout as err:
                _errmsg = u'DNS ERROR: {0}: {1}'.format(str(err),domain_name)
                logger(__meta__[u'shortname'], _method,
                        _errmsg, None, unattended)
                pass
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(
                                            _method,
                                            type(err).__name__,
                                            str(err))
                logger(__meta__[u'shortname'], _method,
                        _errmsg, err, unattended)
                pass
    except Exception as err:
        _errmsg = ERROR_GENERIC.format(_method,
                                                type(err).__name__,
                                                str(err))
        logger(__meta__[u'shortname'], _method, _errmsg, err)
        pass
    # return retrieved ips
    return _domain_ips

def retrieve_Domain_WhoIs(domain_name, unattended=False):
    """  retrieves "whois" information for a given domain name """
    _method = u'retrieve_domain_whois'
    _result = {}
    _data = u''
    _flags = 0
    _flags = _flags | whois.NICClient.WHOIS_QUICK
    try:
        # create code o capture stdout generated by whois
        _stdout = io.StringIO()
        with redirect_stdout(_stdout):
            _whoisinfo = whois.whois(domain_name, flags=_flags)
        for _key in _whoisinfo:
            if (not _key == u'status' and _whoisinfo[_key]
                and _whoisinfo[_key] != u'None'):
                _newkey = _key.replace(u'_', u' ').replace(u' ', u'')
                if type(_whoisinfo[_key]) is list:
                    _result[_newkey] = u', '.join([str(x) for x in _whoisinfo[_key] if x])
                else:
                    _result[_newkey] = _whoisinfo[_key]
    except whois.parser.PywhoisError as err:
        _errstr = str(err).split(u'\n')[0]
        _errmsg = ERROR_GENERIC.format(_method,
                                        type(err).__name__,
                                        _errstr)
        logger(__meta__[u'shortname'], _method, _errmsg,
                    None, unattended)
        _result[u'error'] = _errsmsg
        pass
    except Exception as err:
        _errmsg = ERROR_GENERIC.format(_method,
                                        type(err).__name__,
                                        str(err))
        logger(__meta__[u'shortname'], _method, _errmsg,
                   err, unattended)
        _result[u'error'] = _errsmsg
        pass
    # return whois output
    return _result

def retrieve_GreyNoise(addresses, api_key=None, json_out=False, unattended=False):
    """
        retrieve information from VirusTotal for those IPs that have
        been reported one or more times for abuse in the past
        "maxage" (90) days
    """
    _method = u'retrieve_greynoise'
    _data = None
    _ratelimited = False
    _output = u''
    _request = None
    _results = []
    if type(addresses) is str:
        _addresses = [addresses]
    elif type(addresses) is list:
        _addresses = addresses
    else:
        raise ValueError(u'The "addresses" parameter must be either a '\
                            u'single IP address or a list of IP addresses.')
    _output_string = u''
    if not api_key and not unattended:
        _msg = u'An API key was not provided for GreyNoise. '\
                u'Lookups disabled.'
        utilities.standard_out(_msg, False)
        _output = u'Lookups Disabled'
    else:
        try:
            for _address in _addresses:
                if (utilities.determine_query_type(_address) != u'ipv4' or
                    _ratelimited):
                    #skip non IPV4 addresses
                    continue
                # create "Request" object to source
                _qryurl = templates.GREYNOISE_QUERY.format(_address)
                _request = urlrequest.Request(_qryurl)
                # construct request headers
                _reqhdrs = headers = {u'accept': u'application/json',
                                        u'key': api_key,
                                        u'user-agent': USER_AGENT}
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
                            _data = json.loads(_response.read())
                        else:
                            #reset rate limit flag
                            _ratelimited = False
                except urllib.error.HTTPError as err:
                    if int(err.code) == 429:
                        #set rate limit flag
                        _ratelimited = True
                        _data = {u'query': _address,
                                 u'result': u'rate-limited'}
                    else:
                        _errmsg = u'GreyNoise Error {0} - {1} '\
                                    u''.format(ip_address, err.reason)
                        logger(u'greynoise', _method,
                                    _errmsg, None, unattended)
                        _data = {u'query': _address,
                                 u'result': u'HTTP Error'}
                    pass
                except urllib.error.URLError as err:
                    _errmsg = u'GreyNoise: {0}'.format(err.reason)
                    logger(u'greynoise', _method,
                                _errmsg, err, unattended)
                    _data = {u'query': _address,
                             u'result': u'URL Error'}
                    pass
                except Exception as err:
                    _errmsg = templates.ERROR_GENERIC.format(
                                                    _method,
                                                    type(err).__name__,
                                                    str(err))
                    logger(u'greynoise', _method, _errmsg, None,
                            unattended)
                    _data = {u'query': _address,
                             u'result': str(err)}
                    pass
                _results.append(_data)
        except Exception as err:
            raise err
    # return retrieved data portion
    #return u'\n\n'.join(_collection)
    _output_string = object_to_string(_results, json_out)
    return _output_string

def retrieve_ip_registry(ip_address):
    """
    determines which domain registry contains desired ip information
    and creates html hyperlink to the information for the ip address
    or CIDR address """
    _method = u'retrieve_ip_registry'
    _whoisinfo = None
    _link = None
    try:
        if u'/' in ip_address:
            _ipaddress = ip_address[:ip_address.index(u'/')]
        else:
            _ipaddress= ip_address
        _obj = ipwhois.IPWhois(_ipaddress)
        _whoisinfo = _obj.lookup_rdap()
        _registry = _whoisinfo[u'asn_registry']
        _link = ASN_REGISTRY_LINKS[_registry].format(ip_address)
    except Exception as err:
        _errmsg = ERROR_GENERIC.format(_method,
                                                type(err).__name__,
                                                str(err))
        logger(__meta__[u'shortname'], _method, _errmsg, err)
        pass
    return _link

def retrieve_IP_WhoIs(address, unattended=False):
    """ retrieves "whois" information for a given ip address """
    _method = u'retrieve_IP_WhoIs'
    _whoisinfo = None
    try:
        _data = {}
        _obj = ipwhois.IPWhois(address)
        _whoisinfo = _obj.lookup_rdap()
        if _whoisinfo:
            _data = {u'query': _whoisinfo[u'query'],
                    u'registrant': None,
                    u'address': None,
                    u'asnnum': _whoisinfo[u'asn'],
                    u'asn_cidr': _whoisinfo[u'asn_cidr'],
                    u'asn_country_code': _whoisinfo[u'asn_country_code'],
                    u'net_handle': _whoisinfo[u'network'][u'handle'],
                    u'net_cidr': _whoisinfo[u'network'][u'cidr'],
                    u'net_type': _whoisinfo[u'network'][u'type'],
                    u'net_name': _whoisinfo[u'network'][u'name'],
                    u'net_country': _whoisinfo[u'network'][u'country']}
            if _whoisinfo[u'objects']:
                for _object in _whoisinfo[u'objects']:
                    if (u'roles' not in _whoisinfo[u'objects'][_object] or
                        not _whoisinfo[u'objects'][_object][u'roles']):
                        continue
                    if u'registrant' in _whoisinfo[u'objects'][_object][u'roles']:
                        for _entry in _whoisinfo[u'objects'][_object][u'events']:
                            _key = _entry[u'action'].replace(u' ',u'')
                            _data[_key] = _entry[u'timestamp']
                        try:
                            _data[u'registrant'] = _whoisinfo[u'objects'][_object][u'contact'][u'name']
                        except:
                            pass
                        try:
                            _data[u'address'] = _whoisinfo[u'objects'][_object][u'contact'][u'address'][0][u'value']
                            if _data[u'address']:
                                _data[u'address'].replace(u'\n', u', ')
                        except:
                            pass        
    except Exception as err:
        _errmsg = ERROR_GENERIC.format(_method,
                                                type(err).__name__,
                                                str(err))
        logger(__meta__[u'shortname'], _method, _errmsg, err, unattended)
        pass
    # return collected IP Whois data
    return _data

def retrieve_VT_IP(addresses, api_key=None, json_out=False, unattended=False):
    """
        retrieve information from VirusTotal for those IPs that have
        been reported one or more times for abuse in the past
        "maxage" (90) days
    """
    _method = u'retrieve_virustotal'
    _data = None
    _output = u'No Match'
    _request = None
    _results = []
    if type(addresses) is str:
        _addresses = [addresses]
    elif type(addresses) is list:
        _addresses = addresses
    else:
        raise ValueError(u'The "addresses" parameter must be either a '\
                            u'single IP address or a list of IP addresses.')
    _output_string = u''
    if not api_key and not unattended:
        _msg = u'An API key was not provided for VirusTotal. '\
                u'Lookups disabled.'
        utilities.standard_out(_msg, False)
        _output = u'Lookups Disabled'
    else:
        try:
            for _address in _addresses:        
                # create "Request" object to source
                _qryurl = templates.VT_IP_QUERY.format(_address)
                _guiurl = templates.VT_IP_GUI.format(_address)
                _request = urlrequest.Request(_qryurl)
                # construct request headers
                _reqhdrs = headers = {u'accept': u'application/json',
                                        u'x-apikey': api_key,
                                        u'user-agent': USER_AGENT}
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
                            _data = json.loads(_response.read())
                except urllib.error.HTTPError as err:
                    _errmsg = u'VirusTotal: HTTP {1} - {2} '\
                                u''.format(_address, err.code, err.reason)
                    _data = {u'query': _address,
                                u'error': _errmsg}
                    logger(u'virustotal', _method,
                                _errmsg, None, unattended)
                    pass
                except urllib.error.URLError as err:
                    _errmsg = u'VirusTotal: {0}'.format(err.reason)
                    logger(u'virustotal', _method,
                                _errmsg, err, unattended)
                    pass
                except Exception as err:
                    _errmsg = templates.ERROR_GENERIC.format(
                                                    _method,
                                                    type(err).__name__,
                                                    str(err))
                    logger(u'virustotal', _method, _errmsg, None,
                            unattended)
                    pass                
                _result = {}
                if not u'error' in _data:
                    found_malicious = []
                    if u'harmless' in _data[u'data'][u'attributes'][u'last_analysis_stats']:
                        _data[u'data'][u'attributes'][u'last_analysis_stats'][u'non-malicious'] = \
                            _data[u'data'][u'attributes'][u'last_analysis_stats'][u'harmless']
                        del _data[u'data'][u'attributes'][u'last_analysis_stats'][u'harmless']
                    for _field in sorted(_data[u'data'][u'attributes'][u'last_analysis_stats']):
                        try:
                            _nextfield = _field.lower()
                            if _nextfield == u'harmless':
                                _nextfield = u'non-malicious'
                            _result[u'analysis_{0}'.format(_nextfield.lower())] = str(_data[u'data'][u'attributes'][u'last_analysis_stats'][_field])
                            if _field == u'malicious' and _data[u'data'][u'attributes'][u'last_analysis_stats'][_field]:
                                _tests = _data[u'data'][u'attributes'][u'last_analysis_results']
                                for _source in _tests:
                                    if _tests[_source][u'result'] == u'malicious':
                                        found_malicious.append(_source.replace(u' ', u'_'))
                        except KeyError:
                            pass
                    _result[u'analysis_date'] = None
                    try:
                        _result[u'analysis_date'] = datetime.fromtimestamp(
                                int(_data[u'data'][u'attributes'][u'last_modification_date'])).isoformat()
                    except KeyError:
                        pass

                    if found_malicious:
                        _result[u'found_malicious'] = u'|'.join(found_malicious)
                    _result[u'query'] = _address
                    _result['link'] = u'<a href="{0}" target="_blank">Virustotal'\
                                        u'</a>'.format(_guiurl)
                if _result:
                    _results.append(_result)
            _output_string = object_to_string(_results, json_out)
        except Exception as err:
            raise err
    #return output string
    return _output_string

def retrieve_WhoIs(addresses, json_out=False, unattended=False):
    """
    general method to determine the whois query type execute
    the correct whois query and return the results
    """
    _method = u'Retrieve_WhoIs'
    _results = []
    #_collection = []
    _output_string = u''
    try:
        for _address in addresses:
            _result = None
            _inputstr = _address.strip().lower()
            # see if it is a domain name
            try:
                if QUERY_RGXS[u'hostname'].match(_inputstr):
                    #perform domain name whois
                    _result = retrieve_Domain_WhoIs(_inputstr, unattended)
                elif (u'/' not in _inputstr and
                    (QUERY_RGXS[u'net'].match(_inputstr) or
                    QUERY_RGXS[u'ipv6'].match(_inputstr))):
                    #perform ip address whois
                    _result = retrieve_IP_WhoIs(_inputstr, unattended)
                else:
                    _errmsg = u'The query string provided: "{0}" is not '\
                                u'a recognized type.'.format(_address)
                    raise ValueError(_errmsg)
                if _result:
                    _results.append(_result)            
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(
                                                _method,
                                                type(err).__name__,
                                                str(err))
                logger(u'retrieve_WhoIs', _method, _errmsg, None, unattended)
                pass
            
        _output_string = object_to_string(_results, json_out)
    except Exception as err:        
        _errmsg = templates.ERROR_GENERIC.format(
                                        _method,
                                        type(err).__name__,
                                        str(err))
        logger(u'retrieve_WhoIs', _method, _errmsg, None, unattended)
        _output_string = _errmsg
        pass
    return _output_string

def standard_out(message, returns_input=False):
    """ outputs message to stdout and returns input, if necessary """
    _output = None
    if returns_input:
        _message = u'<?> {0}\n'.format(message).replace(u'\n\n', u'\n')
        _output = input(_message).strip()
    else:
        _message = u'-->{0}\n'.format(message).replace(u'\n\n', u'\n')
        sys.stdout.write(_message)
    return _output



def retrieve_domain_whois(domain_name, unattended=False):
    """  retrieves "whois" information for a given domain name """
    _method = u'retrieve_domain_whois'
    _output = {}
    _data = u''
    _flags = 0
    _flags = _flags | whois.NICClient.WHOIS_QUICK
    try:
        # create code o capture stdout generated by whois
        _stdout = io.StringIO()
        with redirect_stdout(_stdout):
            _whoisinfo = whois.whois(domain_name, flags=_flags)
        for _key in _whoisinfo:
            if (not _key == u'status' and _whoisinfo[_key]
                and _whoisinfo[_key] != u'None'):
                _newkey = _key.replace(u'_', u' ').replace(u' ', u'')
                if type(_whoisinfo[_key]) is list:
                    _output[_newkey] = u', '.join([str(x) for x in _whoisinfo[_key] if x])
                else:
                    _output[_newkey] = _whoisinfo[_key]
    except whois.parser.PywhoisError as err:
        _errstr = str(err).split(u'\n')[0]
        _errmsg = ERROR_GENERIC.format(_method,
                                        type(err).__name__,
                                        _errstr)
        logger(__meta__[u'shortname'], _method, _errmsg,
                    None, unattended)
        _data = u'Unavailable'
        pass
    except Exception as err:
        _errmsg = ERROR_GENERIC.format(_method,
                                        type(err).__name__,
                                        str(err))
        logger(__meta__[u'shortname'], _method, _errmsg,
                   err, unattended)
        _data = u'Unavailable'
        pass
    # construct text output
    if not _output:
        _data = u'No Match'
    else:
        for _key in _output:
            _value = _output[_key]
            if not _value:
                _value = u'null'
            _data += u'{0}: {1}\n'.format(_key, _value)
        _data = u'{0}\n'.format(_data)
    # return whois output
    return _data

def retrieve_ip_whois(ip_address, unattended=False):
    """ retrieves "whois" information for a given ip address """
    _method = u'retrieve_ip_whois'
    _whoisinfo = None
    _data = {}
    try:
        _obj = ipwhois.IPWhois(ip_address)
        _whoisinfo = _obj.lookup_rdap()
        if _whoisinfo:
            _data = {u'query': _whoisinfo[u'query'],
                    u'registrant': None,
                    u'address': None,
                    u'asnnum': _whoisinfo[u'asn'],
                    u'asn_cidr': _whoisinfo[u'asn_cidr'],
                    u'asn_country_code': _whoisinfo[u'asn_country_code'],
                    u'net_handle': _whoisinfo[u'network'][u'handle'],
                    u'net_cidr': _whoisinfo[u'network'][u'cidr'],
                    u'net_type': _whoisinfo[u'network'][u'type'],
                    u'net_name': _whoisinfo[u'network'][u'name'],
                    u'net_country': _whoisinfo[u'network'][u'country']}
            if _whoisinfo[u'objects']:
                for _object in _whoisinfo[u'objects']:
                    if (u'roles' not in _whoisinfo[u'objects'][_object] or
                        not _whoisinfo[u'objects'][_object][u'roles']):
                        continue
                    if u'registrant' in _whoisinfo[u'objects'][_object][u'roles']:
                        for _entry in _whoisinfo[u'objects'][_object][u'events']:
                            _key = _entry[u'action'].replace(u' ',u'')
                            _data[_key] = _entry[u'timestamp']
                        try:
                            _data[u'registrant'] = _whoisinfo[u'objects'][_object][u'contact'][u'name']
                        except:
                            pass
                        try:
                            _data[u'address'] = _whoisinfo[u'objects'][_object][u'contact'][u'address'][0][u'value']
                            if _data[u'address']:
                                _data[u'address'].replace(u'\n', u', ')
                        except:
                            pass
            _output = u''
            for _key in _data:
                _value = _data[_key]
                if not _value:
                    _value = u'null'
                _output += u'{0}: {1}\n'.format(_key, _value)
            _output = u'{0}\n'.format(_output)             
    except Exception as err:
        _errmsg = ERROR_GENERIC.format(_method,
                                                type(err).__name__,
                                                str(err))
        logger(__meta__[u'shortname'], _method, _errmsg, err, unattended)
        pass
    # return colleceted IP Whois data
    return _output



########################################################################
#OLD OLD OLD
########################################################################
"""
def retrieve_abuseip(ip_address, api_key=None, max_age=90, unattended=False):
    
    _method = u'retrieve_abuse_ip'
    _data = None
    _output = u'No Match'
    _qryurl = u'https://api.abuseipdb.com/api/v2/check?ipAddress={0}&maxAgeInDays={1}'
    _guiurl = u'https://www.abuseipdb.com/check/{0}'.format(ip_address)
    _request = None
    if not api_key:
        _msg = u'An API key was not provided for AbuseIPDB. '\
                u'Lookups disabled.'
        utilities.standard_out(_msg, False)
        _output = u'Lookups Disabled'
    else:
        try:
            _request = urlrequest.Request(_qryurl.format(ip_address, max_age))
            # construct request headers
            _reqhdrs = headers = {u'Accept': u'application/json',
                                    u'Key': api_key,
                                    u'User-Agent': USER_AGENT}
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
                        _data = json.loads(_response.read())
            except urllib.error.HTTPError as err:
                _errmsg = u'HTTP {1} - {2} '\
                            u''.format(ip_address, err.code, err.reason)
                _data = {u'query': ip_address,
                            u'error': _errmsg}
                logger(__meta__[u'shortname'], _method,
                            _errmsg, None, unattended)
                pass
            except urllib.error.URLError as err:
                _errmsg = err.reason
                logger(__meta__[u'shortname'], _method,
                            _errmsg, err, unattended)
                pass
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(
                                                _method,
                                                type(err).__name__,
                                                str(err))
                logger(__meta__[u'shortname'], _method, _errmsg, None,
                        unattended)
                pass
            _dict = {}
            if _data and u'data' in _data and _data[u'data']:
                for _key in _data[u'data']:
                    #if not _key.strip().replace(u'_', u'').lower() == u'ipaddress':
                    _dict[_key] = _data[u'data'][_key]
                for _field in _dict:
                    if not _dict[_field]:
                        if _field.startswith(u'is'):
                            _dict[_field] = u'False'
                        else:
                            _dict[_field] = u'0'
                _dict['link'] = u'<a href="{0}" target="_blank">AbuseIPDB'\
                                u'</a>'.format(_guiurl)
            elif u'error' in _data:
                _dict = _data
            # construct ouput string
            if _dict:
                _output = u''
                for _key in sorted(_dict):
                    if not type(_dict[_key]) is list:
                        _output += u'{0}: {1}\n'.format(_key, _dict[_key])
                    else:
                        _output += u'{0}: {1}\n'.format(_key,
                                        u'|'.join([x for x in _dict[_key]]))
        except Exception as err:
            raise err
    # return retrieved data
    return _output

def retrieve_dnsbl(query, qtype):
    
    if qtype.startswith(u'ipv'):
        _checker = pydnsbl.DNSBLIpChecker()
    else: #assumes domain name
        _checker = pydnsbl.DNSBLDomainChecker()
    # retrieve results
    _output = u''
    _result = _checker.check(query)
    _data = {u'blocklisted': str(_result.blacklisted),
                u'block_lists': [str(x) for x in _result.detected_by.keys()],
                u'categories': [x for x in _result.categories],
                u'query': query,                
                u'providers_queried': str(len([x for x in _result.providers]))}
    for _key in _data:
        _value = _data[_key]
        if not _value:
            _value = u'null'
        if type(_value) is list:
            _value = u'\n '.join(_value)
            _output += u'{0}:\n- {1}\n'.format(_key, _value)
        else:
            _output += u'{0}: {1}\n'.format(_key, _value)
    return _output

def retrieve_greynoise(ip_address, api_key=None, unattended=False):
    
    _method = u'retrieve_greynoise'
    _data = None
    _output = u''
    _request = None
    if not api_key and not unattended:
        _msg = u'An API key was not provided for GreyNoise. '\
                u'Lookups disabled.'
        utilities.standard_out(_msg, False)
        _output = u'Lookups Disabled'
    else:
        try:
            # create "Request" object to source
            _qryurl = templates.GREYNOISE_QUERY.format(ip_address)
            _request = urlrequest.Request(_qryurl)
            # construct request headers
            _reqhdrs = headers = {u'accept': u'application/json',
                                    u'key': api_key,
                                    u'user-agent': USER_AGENT}
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
                        _data = json.loads(_response.read())
            except urllib.error.HTTPError as err:
                _errmsg = u'HTTP {1} {2} '\
                            u''.format(ip_address, err.code, err.reason)
                _data = {u'query': ip_address,
                            u'result': _errmsg}
                logger(u'greynoise', _method,
                            _errmsg, None, unattended)
                pass
            except urllib.error.URLError as err:
                _errmsg = err.reason
                logger(u'greynoise', _method,
                            _errmsg, err, unattended)
                pass
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(
                                                _method,
                                                type(err).__name__,
                                                str(err))
                logger(u'greynoise', _method, _errmsg, None,
                        unattended)
                pass
        except Exception as err:
            raise err
    for _key in _data:
        if not _key == u'link':  # and
        #not _key.strip() == u'query'):
            _output += u'{0}: {1}\n'.format(_key, _data[_key])
        else:
            _output += u'{0}: <a href="{1}" target="_blank">GreyNoise</a>\n'.format(_key, _data[_key])
    # return retrieved data portion
    return _output

def retrieve_vt_ip(ip_address, api_key=None, json_out=False, unattended=False):
    
    _method = u'retrieve_virustotal'
    _data = None
    _output = u'No Match'
    _request = None
    if not api_key and not unattended:
        _msg = u'An API key was not provided for VirusTotal. '\
                u'Lookups disabled.'
        utilities.standard_out(_msg, False)
        _output = u'Lookups Disabled'
    else:
        try:
            # create "Request" object to source
            _qryurl = templates.VT_IP_QUERY.format(ip_address)
            _guiurl = templates.VT_IP_GUI.format(ip_address)
            _request = urlrequest.Request(_qryurl)
            # construct request headers
            _reqhdrs = headers = {u'accept': u'application/json',
                                    u'x-apikey': api_key,
                                    u'user-agent': USER_AGENT}
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
                        _data = json.loads(_response.read())
            except urllib.error.HTTPError as err:
                _errmsg = u'HTTP {1} - {2} '\
                            u''.format(ip_address, err.code, err.reason)
                _data = {u'query': ip_address,
                            u'error': _errmsg}
                logger(u'virustotal', _method,
                            _errmsg, None, unattended)
                pass
            except urllib.error.URLError as err:
                _errmsg = err.reason
                logger(u'virustotal', _method,
                            _errmsg, err, unattended)
                pass
            except Exception as err:
                _errmsg = templates.ERROR_GENERIC.format(
                                                _method,
                                                type(err).__name__,
                                                str(err))
                logger(u'virustotal', _method, _errmsg, None,
                        unattended)
                pass
            _output = {}
            if not u'error' in _data:
                found_malicious = []
                if u'harmless' in _data[u'data'][u'attributes'][u'last_analysis_stats']:
                    _data[u'data'][u'attributes'][u'last_analysis_stats'][u'non-malicious'] = \
                        _data[u'data'][u'attributes'][u'last_analysis_stats'][u'harmless']
                    del _data[u'data'][u'attributes'][u'last_analysis_stats'][u'harmless']
                for _field in sorted(_data[u'data'][u'attributes'][u'last_analysis_stats']):
                    _nextfield = _field.lower()
                    if _nextfield == u'harmless':
                        _nextfield = u'non-malicious'
                    _output[u'analysis_{0}'.format(_nextfield.lower())] = str(_data[u'data'][u'attributes'][u'last_analysis_stats'][_field])
                    if _field == u'malicious' and _data[u'data'][u'attributes'][u'last_analysis_stats'][_field]:
                        _tests = _data[u'data'][u'attributes'][u'last_analysis_results']
                        for _source in _tests:
                            if _tests[_source][u'result'] == u'malicious':
                                found_malicious.append(_source.replace(u' ', u'_'))
                _output[u'analysis_date'] = datetime.fromtimestamp(
                            int(_data[u'data'][u'attributes'][u'last_modification_date'])).isoformat()
                if found_malicious:
                    _output[u'found_malicious'] = u'|'.join(found_malicious)
                _output[u'query'] = ip_address
                _output['link'] = u'<a href="{0}" target="_blank">Virustotal'\
                                    u'</a>'.format(_guiurl)
        except Exception as err:
            raise err
    _data = u''
    for _key in _output:
        _data += u'{0}: {1}\n'.format(_key, _output[_key])
    # return retrieved data portion
    return _data

def retrieve_whois(input_string, unattended=False):
    
    _inputstr = input_string.strip().lower()
    # see if it is a domain name
    if QUERY_RGXS[u'hostname'].match(_inputstr):
        #perform domain name whois
        _results = retrieve_domain_whois(_inputstr, unattended)
    elif (u'/' not in _inputstr and
        (QUERY_RGXS[u'net'].match(_inputstr) or
        QUERY_RGXS[u'ipv6'].match(_inputstr))):
        #perform ip address whois
        _results = retrieve_ip_whois(_inputstr, unattended)
    else:
        _errmsg = u'The query string provided: "{0}" is not '\
                    u'a recognized type.'.format(input_string)
        raise ValueError(_errmsg)
    return _results
"""
