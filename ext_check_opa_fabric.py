#!/usr/bin/python

# check opa fabric
#

# Credits:
#
# Scripting: Josef Dvoracek


import os.path
import sys

import yaml  # config file parsing

import logging.handlers

from time import sleep, time

from daemon import Daemon
from icinga import Icinga

# project-imports

from fabric import FabricInfoCollector
from fabric_checker import FabricChecker
from helpers import *

tool_name = "check_opa_fabric"  # our name


# functions:

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


# main daemon function -

class check_opa_fabric_daemon(Daemon):

    def __init__(self, conf, logger, pidfile='/tmp/opastats.pid', stdin='/dev/null', stdout='/tmp/opastats.stdout', stderr='/tmp/opastats.stdout'):

        Daemon.__init__(self, pidfile, stdin, stdout, stderr)
        self.config = conf
        self.logger = logger
        logger.info(tool_name + " starting at %s", time())

    def run(self):
        self.logger.info("main thread started..")

        # main loop

        i = 0

        while True and int(i) is not int(5):
            try:
                self.logger.info("hey here is run()")
                i = i + 1
                pass
            except:
                self.logger.exception('exception: ')
            sleep(3)  # 133 seconds = 2mins+-   #FIXME 30 is not much.


# main: ----------------------------------------------------------------------------------------------------------------

start_time = timeit.default_timer()

# get config from config file - the config file path is now hardcoded.. :(

config_file_path = os.path.abspath("/usr/local/monitoring/ext_check_opa_fabric.conf")
conf = get_config(config_file_path)

error_counters = FabricChecker.get_error_counters_from_config(conf)  # parse counters and their thresholds:

# setup logging:

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler = logging.handlers.RotatingFileHandler('/var/log/check_opa_fabric.log', maxBytes=20 * 1024 * 1024, backupCount=5)
handler.setFormatter(formatter)
logger = logging.getLogger(tool_name)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)  # could be done better. for example with some config :)

logger.info("logging setup done.")

# start daemon

# daemon = check_opa_fabric_daemon(conf,logger)
# daemon.start()

# sys.exit(1) #TBF

# #fixme: stop now.

debug = False

runtime_info_message("Collecting data from fabric", start_time)

fabric_info = FabricInfoCollector()

runtime_info_message("Processing nodes", start_time)

# iterate over nodes and checks good and bad things:

for node in fabric_info.node2guid:  # provide results for nodes

    os = ""  # reset output string
    crit = False
    warn = False

    try:
        (r_crit, r_warn, r_os) = FabricChecker.check_port(fabric_info.get_node_remote_port_errors(node), error_counters)
        (l_crit, l_warn, l_os) = FabricChecker.check_port(fabric_info.get_node_local_port_errors(node), error_counters)
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

    os = str(os) + '\n'  # append newline to create the separator for icinga..
    os = str(os) + Icinga.create_local_port_status_string(l_os)  # local port
    os = str(os) + Icinga.create_remote_port_status_string(r_os, fabric_info.get_node_remote_port_nodedesc(node), fabric_info.get_node_remote_port_portnr(node))  # remote port.

    node_fqdn = str(node) + str(conf['node_to_fqdn_suffix'])

    oc = Icinga.STATE_OK
    if warn:
        oc = Icinga.STATE_WARNING
    if crit:
        oc = Icinga.STATE_CRITICAL

    result = Icinga.post_check_result(conf, conf['api_host'], int(conf['api_port']), str(node_fqdn), "external-poc-OPA-quality", int(oc), str(os), conf['check_source'])

runtime_info_message("Processing top level switches", start_time)

for switch in fabric_info.top_level_switches:
    icinga_hostname = str(switch) + str(conf['node_to_fqdn_suffix'])
    FabricChecker.check_switch_interswitch_links_count(switch, icinga_hostname, conf['top_level_switch_downlinks_count'], fabric_info, conf)  # amount of interswitch links:
    FabricChecker.check_switch_ports(switch, icinga_hostname, fabric_info, conf)  # downlink port health:

runtime_info_message("Processing spine-card-switches", start_time)

spines = conf['spines']

for spine in spines:
    icinga_hostname = str(spine).replace(' ', '_')  # in icinga there are no spaces allowed there in object naming
    FabricChecker.check_switch_ports(spine, icinga_hostname, fabric_info, conf)

runtime_info_message("spine switches done", start_time)

others = conf['others']

for switch in others:
    icinga_hostname = str(switch).replace(' ', '_')  # in icinga there are no spaces allowed there in object naming
    FabricChecker.check_switch_ports(switch, icinga_hostname, fabric_info, conf)

runtime_info_message("other switches done", start_time)
