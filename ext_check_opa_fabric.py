#!/usr/bin/python

# check opa fabric
#

# Credits:
#
# Scripting: Josef Dvoracek


import os.path
import sys
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


def check_port(port_error_counters, hide_good=False):
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

    portcount = fabric_info.get_switch_inter_switch_port_count(switch)

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
                (r_crit, r_warn, r_os) = check_port(fabric_info.get_switch_remote_port_errors(switch, port), hide_good=True)  # we don't want to see good ports, bcs. there is too much of them
                (l_crit, l_warn, l_os) = check_port(fabric_info.get_switch_local_port_errors(switch, port), hide_good=True)

                if r_crit or l_crit:
                    crit = True
                if r_warn or l_warn:
                    warn = True

                if l_crit or l_warn:
                    os_links = str(os_links) + "<p><b> local port " + str(port) + " is not healthy: </b></p>"
                    os_links = str(os_links) + str(l_os)

                if r_crit or r_warn:
                    os_links = str(os_links) + "<p><b> remote port connected to port " + str(port) + ", " + str(fabric_info.get_switch_remote_port_nodedesc(switch, port)) + "(port nr. " + str(fabric_info.get_switch_remote_port_portnr(switch, port)) + ") is not healthy: </b></p>"
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

        post_check_result(conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", int(oc_links), str(os_links), conf['check_source'], debug=False)
    except KeyError:
        # this exception means there is port down on the switch. This is not unusual state.
        post_check_result(conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", 3, "switch unreachable", conf['check_source'], debug=False)


def create_local_port_status_string(port_counters=None):
    os = ""

    os = str(os) + "<p>"
    os = str(os) + "<b>Local port summary</b>"
    os = str(os) + str(port_counters)
    os = str(os) + '</p>'

    return os


def create_remote_port_status_string(port_counters=None, remote_port_nodedesc=None, remote_port_portnr=None):
    os = ""

    os = str(os) + "<p>"
    os = str(os) + "<b>Remote port ( nodedesc: " + str(remote_port_nodedesc) + ", port: " + str(remote_port_portnr) + " ) summary</b>"
    os = str(os) + str(port_counters)
    os = str(os) + "</p>"

    return os


def get_config(config_file_path, debug=False):
    if os.path.isfile(config_file_path):
        config_file = open(config_file_path, 'r')
        conf = yaml.safe_load(config_file)
        if debug:
            print "conf"
            print str(conf)
            print "end of conf"
        config_file.close()
        return conf
    else:
        print "Err: No config file found"
        sys.exit(2)


def get_error_counters_from_config(conf):
    error_counters = {}
    for item in conf['thresholds']:
        counter_name = str(item['counter'])
        error_counters[counter_name] = {}
        error_counters[counter_name]['crit'] = item['crit']
        error_counters[counter_name]['warn'] = item['warn']

    if debug:
        print str(error_counters)

    return error_counters


# main: ----------------------------------------------------------------------------------------------------------------

start_time = timeit.default_timer()

# get config from config file - the config file path is now hardcoded.. :(

config_file_path = os.path.abspath("/usr/local/monitoring/ext_check_opa_fabric.conf")
conf = get_config(config_file_path)

debug = False

# parse counters and their thresholds:

error_counters = get_error_counters_from_config(conf)

runtime_info_message("Collecting data from fabric", start_time)

fabric_info = FabricInfoCollector()

runtime_info_message("Processing nodes", start_time)

# iterate over nodes and checks good and bad things:

for node in fabric_info.node2guid:  # provide results for nodes

    os = ""  # reset output string
    crit = False
    warn = False

    try:
        (r_crit, r_warn, r_os) = check_port(fabric_info.get_node_remote_port_errors(node))
        (l_crit, l_warn, l_os) = check_port(fabric_info.get_node_local_port_errors(node))
    except KeyError:
        #    raise  #for debug uncomment
        continue  # there are some data missing, let's take different node

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

    os = str(os) + '\n' #append newline to create the separator for icinga..
    os = str(os) + create_local_port_status_string(l_os)    #local port
    os = str(os) + create_remote_port_status_string(r_os, fabric_info.get_node_remote_port_nodedesc(node), fabric_info.get_node_remote_port_portnr(node))   #remote port.

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
