#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Description
# ######################################################################

    File Name:      templates.py
    Version:        1.0
    Created:        April 28, 2022
    Last Edited:    July 5, 2022
    Author:         <dmranta>[@]<cert.org>

    Description:    File containing template strings used to support
                    functionality of Threat Manager objects

# ######################################################################
"""
# load required 3rd party libraries
LOAD_ERROR = u'The "{0}" library is required for operation.\n'\
                u'It is available at: {1}\n'\
                u'Or may be installed using: "pip[3] install {0}" '\
                u'from the command line.\n'

ST_API_NEW_URL = u'https://api.securitytrails.com/v1/feeds/'\
                        u'domains/registered/?apikey={0}'
# shodan query limit API request
SH_API_CREDITS_URL = u'https://api.shodan.io/api-info?key={0}'
# Template for creating hyperlinks to NIST NVD CVE resources
NVD_CVE_LINK = u'<a href="https://nvd.nist.gov/vuln/detail/{0}" '\
                                        u'target="_blank">{1}</a>'

# Template for creating hyperlinks to non-CVE NIST NVD resources
NVD_QUERY_LINK = u'<a href="https://nvd.nist.gov/vuln/search/results?'\
                            u'form_type=Basic&results_type=overview&'\
                            u'query={0}" target="_blank">{1}</a>'

# Template for creating NIST NVD API CPE string queries
NVD_CPE_QUERY = u'https://services.nvd.nist.gov/rest/json/cves/1.0?'\
                    u'apiKey={0}&cpeMatchString={1}'

ABUSE_IP_QUERY = u'https://api.abuseipdb.com/api/v2/check?'\
                    u'ipAddress={1}&maxAgeInDays=90'

#Template for GreyNoise IP lookup
GREYNOISE_QUERY = u'https://api.greynoise.io/v3/community/{0}'

# template for link to query VT api
VT_IP_QUERY =u'https://www.virustotal.com/api/v3/ip_addresses/{0}'
# template for creating hyperlink to VT resource page
VT_IP_GUI = u'https://www.virustotal.com/gui/ip-address/{0}'

ERROR_GENERIC = u' Method: {0} Type: {1} Msg: {2}'

TEMPLATE_CSV = u'"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}"'

# Template for base HTML page output container
HTML_BASE= u"""<html>\n<head>\n
<title>{0}</title>\n
<style>\n
{1}\n
</style>\n
<script type="text/javascript">\n
{2}\n
</script>\n
</head>\n
<body>\n
{3}\n
{4}\n
<hr>
{5}\n
</body>\n
</html>"""

# CSS styling for results HTML page
PAGE_STYLE = """
    body{\nbackground-color: #e9f5fd;\n}\n
    a{\ncolor: #00344d;\n}\n
    hr{\nborder-top: 1px solid #e6f5ff;\n
        border-bottom: 0px;}\n
    table{\nborder-spacing: 0px;\n
                border: collapse;}\n
                width: 95%;\n}\n
    tr{\nborder:1px solid white;\n}\n
    tr:hover{\nbackground-color: #e6f5ff;\n
                border: 1px solid #0088cc;\n
                color: #00344d;\n}\n
    th{\nbackground-color: #969696;\n
                color: white;\n
                font-size: 10px;\n
                font-family: sans-serif;\n
                font-weight: bold;\n
                //height: 15px;\n
                text-align: center;\n
                vertical-align: middle;\n
                border-style: none solid none solid;\n
                broder-width: 1px;\n
                border-color: white;\n}\n
    th:hover{\ncursor: pointer;\n
                font-style: italic;\n
                text-decoration-line: underline;\n}\n
    td{\nfont-family: sans-serif;\n
                font-size: 11px;\n
                vertical-align: top;\n
                padding: 2px;\n}\n
    #table-wrapper{\nposition: relative;\n
                box-shadow: 4px 4px 4px #777777;\n
                margin: 0px;\n
                background-color: white;\n}\n
    #table-wrapper table{width: 100%;}\n
    #table-scroll{\noverflow: auto;\n
                height: 720px;\n
                margin-top: 10px;\n}\n
    #banner{\nfont-size: 12px;\n}\n
    #header{\nfont-family: sans-serif;\n
                font-size: 20px;\n
                color: white;\n
                background-color: #003d66;\n
                text-align: center;\n
                box-shadow: 4px 4px 4px #777777;\n
                padding: 6px;\n
                margin: 0px;\n}\n
    footer{\nfont-family: sans-serif;\n
                font-size: 10px;\n
                text-align: center;\n}\n
    button{\nfont-size: 10px;\n
                color: lightgrey;\n
                text-decoration: underline;\n
                padding: 3px;\n
                margin: 3px;\n
                background: none;\n
                border: 1px solid #005580;\n
                box-shadow: none;\n}\n
    button:hover{\ncursor: pointer;\n
                background-color: #0088cc;\n
                color: white;\n
                border: 1px solid white;\n}\n"""

# JavaScript to include in HTML output page to support column sorting
# and persistimng displayed output to file
JAVA_SCRIPT = u"""//Sourced from - https://codepen.io/andrese52/pen/ZJENqp\n
function sortTable(n) {
  var table,
    rows,
    switching,
    i,
    x,
    y,
    shouldSwitch,
    dir,
    switchcount = 0;
  table = document.getElementById("results");
  switching = true;
  //Set the sorting direction to ascending:
  dir = "asc";
  /*Make a loop that will continue until
  no switching has been done:*/
  while (switching) {
    //start by saying: no switching is done:
    switching = false;
    rows = table.getElementsByTagName("tr");
    /*Loop through all table rows (except the
    first, which contains table headers):*/
    for (i = 1; i < rows.length - 1; i++) { //Change i=0 if you have the header th a separate table.
      //start by saying there should be no switching:
      shouldSwitch = false;
      /*Get the two elements you want to compare,
      one from current row and one from the next:*/
      x = rows[i].getElementsByTagName("td")[n];
      y = rows[i + 1].getElementsByTagName("td")[n];
      /*check if the two rows should switch place,
      based on the direction, asc or desc:*/
      if (dir == "asc") {
        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
          //if so, mark as a switch and break the loop:
          shouldSwitch = true;
          break;
        }
      } else if (dir == "desc") {
        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
          //if so, mark as a switch and break the loop:
          shouldSwitch = true;
          break;
        }
      }
    }
    if (shouldSwitch) {
      /*If a switch has been marked, make the switch
      and mark that a switch has been done:*/
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
      //Each time a switch is done, increase this count by 1:
      switchcount++;
    } else {
      /*If no switching has been done AND the direction is "asc",
      set the direction to "desc" and run the while loop again.*/
      if (switchcount == 0 && dir == "asc") {
        dir = "desc";
        switching = true;
      }
    }
  }
}

function downloadCSVFile(){
    // Variable to store the final csv data
	var csv_data = [];

	// Get each row data
	var rows = document.getElementsByTagName('tr');
	for (var i = 0; i < rows.length; i++) {

		// Get each column data
		var cols = rows[i].querySelectorAll('td,th');

		// Stores each csv row data
		var csvrow = [];
		for (var j = 0; j < cols.length; j++) {

			// Get the text data of each cell of
			// a row and push it to csvrow removing hyperlinks
			csvrow.push(cols[j].innerHTML.replace(/<\/?a[^<]*>/g,""));
		}

		// Combine each column value with comma
		csv_data.push(csvrow.join(","));
	}
	// combine each row data with new line character
	csv_data = csv_data.join('\\n');

    // Create CSV file object and feed our
    // csv_data into it
    CSVFile = new Blob([csv_data], { type: "text/csv" });

    // Create to temporary link to initiate
    // download process
    var temp_link = document.createElement('a');

    // Download csv file
    var fpath = window.location.pathname.split("/").slice(-1);
    temp_link.download = fpath + ".csv";
    var url = window.URL.createObjectURL(CSVFile);
    temp_link.href = url;

    // This link should not be displayed
    temp_link.style.display = "none";
    document.body.appendChild(temp_link);

    // Automatically click the link to trigger download
    temp_link.click();
    document.body.removeChild(temp_link);
}
"""

# Template for HTML table container (<div>)
HTML_TABLE = """<div id="table-wrapper">\n
<div id="table-scroll">\n
<table id="results">\n{0}\n</table>
</div>\n
</div>"""

# Template for creating the HTML output page header information
CONTENT_HEADER = """<div id="header">\n<b>{0}</b>\n<br>
<font id="banner">
{1}
</font>\n
<br>\n
</div>\n"""
#u'<button type="button" onclick="downloadCSVFile();">'\
#u'Save Results to File</button>\n'\
#u'</div>\n'

# Template for individual header entries
#HEADER_ENTRY = u'{0}: {1}&nbsp;&nbsp;'
# Template for creating HTML page footer
PAGE_FOOTER = u'<footer>\nVer. {0} - &copy; {1} - {2}\n</footer>'


