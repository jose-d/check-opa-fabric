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
                i = i + 1  # TODO: this is just dummy counter and this should be removed for production

                # main loop logic here
                logger.info("Collecting data from fabric")
                fabric_info = FabricInfoCollector()
                logger.info("Processing nodes")
                for node in fabric_info.node2guid:  # provide results for nodes
                    FabricChecker.check_node_port_health(node, fabric_info, conf)

                for switch in fabric_info.top_level_switches:
                    icinga_hostname = str(switch) + str(conf['node_to_fqdn_suffix'])

                    FabricChecker.check_switch_interswitch_links_count(switch, icinga_hostname, conf['top_level_switch_downlinks_count'], fabric_info, conf)  # amount of interswitch links:
                    FabricChecker.check_switch_ports(switch, icinga_hostname, fabric_info, conf)  # downlink port health:

                spines = conf['spines']

                for spine in spines:
                    icinga_hostname = str(spine).replace(' ', '_')  # in icinga there are no spaces allowed there in object naming
                    FabricChecker.check_switch_ports(spine, icinga_hostname, fabric_info, conf)

                others = conf['others']

                for switch in others:
                    icinga_hostname = str(switch).replace(' ', '_')  # in icinga there are no spaces allowed there in object naming
                    FabricChecker.check_switch_ports(switch, icinga_hostname, fabric_info, conf)

                # end of main loop logic.
                pass
            except:
                self.logger.exception('exception: ')
            sleep(3)  # 133 seconds = 2mins+-   #FIXME 30 is not much.


# main: ----------------------------------------------------------------------------------------------------------------

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

# start daemon:

daemon = check_opa_fabric_daemon(conf, logger)
daemon.start()

sys.exit(0)  # inbetween there is fork of our process, so we can end this one.
