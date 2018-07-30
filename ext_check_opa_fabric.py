#!/usr/bin/python

# check opa fabric
#

# Credits:
#
# Scripting: Josef Dvoracek


import csv  # to parse CSV from intel OPA tools
import os.path
import re  # regular expression parsing to detect the opareport link
import sys
import timeit
from urlparse import urlparse  # URL validation

import requests  # to be able send passive checks result to Icinga2 API
import yaml  # config file parsing
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # to be able to modify warning for SSL

# project-imports

from fabric import FabricInfoCollector
from helpers import *


# functions:

def prepare_session(http_user, http_password):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # disable SSL warning

    session = requests.Session()  # let's use session - it will speed-up the POST-ing, and also it will let us create cleaner code. Little bit.
    session.trust_env = False  # we don't want any variables from env.
    session.auth = (http_user, http_password)  # auth credentials
    session.verify = False  # verify SSL?

    return session


def post_check_result(icinga_server, icinga_server_port, host, check, status, output, source, debug=False):
    if debug: print "posting.."

    url = 'https://' + str(icinga_server) + ":" + str(icinga_server_port) + '/v1/actions/process-check-result?service=' + str(host) + '!' + str(check)

    session = prepare_session(conf['api_user'], conf['api_pass'])

    try:
        r = session.post(url, json={'exit_status': str(status), 'plugin_output': str(output), 'check_source': str(source)}, headers={'Accept': 'application/json', 'Connection': 'close'})
        if debug: print str(r)
        if r.status_code == 200:
            return True
        else:
            return False
    except:
        if debug: raise
        return False


def uri_validator(x):
    try:
        result = urlparse(x)
        return result.scheme and result.netloc and result.path
    except:
        return False


def check_indicator(value, name, ok_values, warning_values, hide_good=False):
    critical = False
    warning = False

    if str(value) in ok_values:
        if hide_good:
            message = ""
            pass
        else:
            message = "[OK] indicator " + str(name) + " has reference value, " + str(value) + "/" + str(ok_values) + "."
    elif str(value) in warning_values:
        message = "[WARNING] indicator " + str(name) + " is at warning level, " + str(value) + "/" + str(ok_values) + "."
        warning = True
    else:
        message = "[CRITICAL] indicator " + str(name) + " is at critical level, " + str(value) + "/" + str(ok_values) + "."
        critical = True

    if critical:
        rc = Icinga.STATE_CRITICAL
    elif warning:
        rc = Icinga.STATE_WARNING
    else:
        rc = Icinga.STATE_OK

    return (rc, message)


def process_check_output(crit, warn, os, rc, message):
    l_crit = crit
    l_warn = warn
    l_os = os

    if rc == Icinga.STATE_CRITICAL:
        l_crit = True
    elif rc == Icinga.STATE_WARNING:
        l_warn = True
    l_os = str(l_os) + '<p>' + str(message) + '</p>'

    return (l_crit, l_warn, l_os)


def parse_node_from_nodedesc(node_desc):
    return node_desc.split(' ')[0].strip()


def check_port(port_error_counters, fabric, hide_good=False):
    crit = False
    warn = False
    os = ""

    # LinkQualityIndicator
    (rc, message) = check_indicator(port_error_counters['LinkQualityIndicator'], 'LinkQualityIndicator', ['5'], ['4'], hide_good)
    (crit, warn, os) = process_check_output(crit, warn, os, rc, message)

    # LinkSpeedActive
    (rc, message) = check_indicator(port_error_counters['LinkSpeedActive'], 'LinkSpeedActive', ['25Gb'], [], hide_good)
    (crit, warn, os) = process_check_output(crit, warn, os, rc, message)

    # LinkWidthDnGradeTxActive
    (rc, message) = check_indicator(port_error_counters['LinkWidthDnGradeTxActive'], 'LinkWidthDnGradeTxActive', ['4'], [], hide_good)
    (crit, warn, os) = process_check_output(crit, warn, os, rc, message)

    # LinkWidthDnGradeRxActive
    (rc, message) = check_indicator(port_error_counters['LinkWidthDnGradeRxActive'], 'LinkWidthDnGradeRxActive', ['4'], [], hide_good)
    (crit, warn, os) = process_check_output(crit, warn, os, rc, message)

    # all "simple" err counters - we're checking if number is higher than some threshold.
    for counter in error_counters:
        bad = False
        rs = "[OK]"
        value = int(port_error_counters[counter])

        if value > error_counters[counter]['warn']:
            warn = True
            bad = True
            rs = "[WARNING]"
        if value > error_counters[counter]['crit']:
            bad = True
            crit = True
            rs = "[CRITICAL]"
        if bad or not hide_good:
            os = os + '<p>' + str(rs) + ":" + str(counter) + " " + str(value) + "</p>"

    return (crit, warn, os)


def check_switch_interswitch_links_count(switch, switch_icinga_hostname, expected_port_count, fabric_info):
    oc = Icinga.STATE_OK
    os = ""

    # count the ports:
    portcount = 0

    for port in fabric_info.opa_errors[switch]:
        portcount = portcount + 1

    if int(expected_port_count) != int(portcount):
        os = "[WARNING] different (" + str(portcount) + ") than expected (" + str(conf['top_level_switch_downlinks_count']) + ") downlinks port count found on this switch."
        oc = Icinga.STATE_WARNING
    else:
        os = "[OK] expected downlinks port count found (" + str(portcount) + ") there on " + str(switch)
        oc = Icinga.STATE_OK

    result = post_check_result(conf['api_host'], int(conf['api_port']), switch_icinga_hostname, "external-poc-downlink-port-count", int(oc), str(os), conf['check_source'])


def check_switch_ports(switch, switch_icinga_hostname, fabric_info):
    os_links = ""
    oc_links = Icinga.STATE_OK
    warn = False
    crit = False

    try:

        for port in fabric_info.inter_switch_links[switch]:
            try:
                local_errors = fabric_info.opa_errors[switch][int(port)]

                remote_switch_nodedesc = fabric_info.inter_switch_links[switch][port][0]
                remote_switch_portnr = fabric_info.inter_switch_links[switch][port][1]
                remote_errors = fabric_info.opa_errors[remote_switch_nodedesc][int(remote_switch_portnr)]

                (r_crit, r_warn, r_os) = check_port(remote_errors, fabric_info.fabric, hide_good=True)  # we don't want to see good ports, bcs. there is too much of them
                (l_crit, l_warn, l_os) = check_port(local_errors, fabric_info.fabric, hide_good=True)

                if r_crit or l_crit:
                    crit = True
                if r_warn or l_warn:
                    warn = True

                if l_crit or l_warn:
                    os_links = str(os_links) + "<p><b> local port " + str(port) + " is not healthy: </b></p>"
                    os_links = str(os_links) + str(l_os)

                if r_crit or r_warn:
                    os_links = str(os_links) + "<p><b> remote port connected to port " + str(port) + ", " + str(remote_switch_nodedesc) + " is not healthy: </b></p>"
                    os_links = str(os_links) + str(r_os)

            except KeyError:
                print "err: key missing"
                raise
                pass

        if crit:
            oc_links = Icinga.STATE_CRITICAL
            os_links = "[CRITICAL] - problems found on switch ports \n" + str(os_links)
        elif warn:
            oc_links = Icinga.STATE_WARNING
            os_links = "[WARNING] - problem found on switch ports \n" + str(os_links)
        else:
            os_links = "[OK] - switch ports are OK \n" + str(os_links)

        result = post_check_result(conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", int(oc_links), str(os_links), conf['check_source'], debug=False)
    except KeyError:
        result = post_check_result(conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", 3, "switch unreachable", conf['check_source'], debug=False)


class Stats():

    def __init__(self):
        self.stats = {}

    def save_stat(self, fabric, node, value, metricname):
        if metricname not in self.stats:  # if not yet there, we will define default values
            self.stats[metricname] = {}
            self.stats[metricname]['min'] = int(+9999)
            self.stats[metricname]['max'] = int(-9999)

        if int(value) > int(self.stats[metricname]['max']):  # if bigger than maximum, save it as new maximum
            self.stats[metricname]['max'] = value
        elif int(value) < int(self.stats[metricname]['min']):  # if smaller than minimum, save it as new minimum
            self.stats[metricname]['min'] = value

    def __str__(self):
        return "stats (dummy _str_ function..)\n" + str(self.stats) + "end of stats\n"


# main: ----------------------------------------------------------------------------------------------------------------

start_time = timeit.default_timer()

# get config from config file - the config file path is now hardcoded.. :(

config_file_path = os.path.abspath("/usr/local/monitoring/ext_check_opa_fabric.conf")

debug = False

if os.path.isfile(config_file_path):
    config_file = open(config_file_path, 'r')
    conf = yaml.safe_load(config_file)
    if debug:
        print "conf"
        print str(conf)
        print "end of conf"
    config_file.close()
else:
    print "Err: No config file found"
    sys.exit(2)

# parse counters and their thresholds:

error_counters = {}
for item in conf['thresholds']:
    counter_name = str(item['counter'])
    error_counters[counter_name] = {}
    error_counters[counter_name]['crit'] = item['crit']
    error_counters[counter_name]['warn'] = item['warn']

if debug:
    print str(error_counters)

runtime_info_message("Collecting data from fabric", start_time)

fabric_info = FabricInfoCollector()

runtime_info_message("Processing nodes", start_time)

# iterate over nodes and checks good and bad things:

# stats structure
stats = Stats()

for node in fabric_info.node2guid:  # provide results for nodes

    # reset the loop variables where needed:
    os = ""

    try:
        # parse data from fabric data structures:

        nb = fabric_info.fabric[fabric_info.node2guid[node]]['nb']  # get neighboor node guid
        nb_image = fabric_info.node_guid_to_system_image_guid[nb[0]]  # convert to image guid

        remote_errors = fabric_info.opa_errors[str(nb[2]).strip()][int(nb[1])]  # get error data structure for remote port
        local_errors = fabric_info.fabric[fabric_info.node2guid[node]]['opa_extract_error']  # get error data structure for local port

        local_lid = fabric_info.fabric[fabric_info.node2guid[node]]['opa_extract_lids']['LID']

        remote_port_guid = nb[0]
        remote_port_portnr = nb[1]
        remote_port_nodedesc = nb[2]

    except KeyError:
        #    raise  #for debug uncomment
        continue  # there are some data missing, let's take different node

    crit = False
    warn = False

    (r_crit, r_warn, r_os) = check_port(remote_errors, fabric_info.fabric)
    (l_crit, l_warn, l_os) = check_port(local_errors, fabric_info.fabric)

    # process return code:
    if r_crit or l_crit:
        crit = True
    elif r_warn or l_warn:
        warn = True

    # header for the output

    if l_crit or l_warn:
        os = str(os) + "local port problem"
    if r_crit or r_warn:
        os = str(os) + "remote port problem"

    if not (l_crit or l_warn) and not (r_crit or r_warn):
        os = str(os) + "[OK] - both sides of link are OK"

    os = str(os) + '\n'

    os = str(os) + "<p>"
    os = str(os) + "<b>Local port summary</b>"
    os = str(os) + str(l_os)
    os = str(os) + '</p>'

    os = str(os) + "<p>"
    os = str(os) + "<b>Remote port summary</b>"
    os = str(os) + str(r_os)
    os = str(os) + "</p>"

    node_fqdn = str(node) + str(conf['node_to_fqdn_suffix'])

    oc = Icinga.STATE_OK
    if warn:
        oc = Icinga.STATE_WARNING
    if crit:
        oc = Icinga.STATE_CRITICAL

    result = post_check_result(conf['api_host'], int(conf['api_port']), str(node_fqdn), "external-poc-OPA-quality", int(oc), str(os), conf['check_source'])

runtime_info_message("Processing top level switches", start_time)

for switch in fabric_info.top_level_switches:
    icinga_hostname = str(switch) + str(conf['node_to_fqdn_suffix'])
    check_switch_interswitch_links_count(switch, icinga_hostname, conf['top_level_switch_downlinks_count'], fabric_info)  # amount of interswitch links:
    check_switch_ports(switch, icinga_hostname, fabric_info)  # downlink port health:

runtime_info_message("Processing spine-card-switches", start_time)

spines = conf['spines']

for spine in spines:
    icinga_hostname = str(spine).replace(' ', '_')  # in icinga there are no spaces allowed there in object naming
    check_switch_ports(spine, icinga_hostname, fabric_info)

runtime_info_message("spine switches done", start_time)

others = conf['others']

for switch in others:
    icinga_hostname = str(switch).replace(' ', '_')  # in icinga there are no spaces allowed there in object naming
    check_switch_ports(switch, icinga_hostname, fabric_info)

runtime_info_message("other switches done", start_time)
