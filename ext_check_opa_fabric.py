#!/usr/bin/python

# check opa fabric
#

# Credits:
#
# Scripting: Josef Dvoracek


# standard-imports
import os.path
import sys
import yaml  # config file parsing
import logging.handlers
from time import sleep, time
from daemon import Daemon
from icinga import Icinga

import timeit

# project-imports
from fabric import FabricInfoCollector
from fabric_checker import FabricChecker
from tsdb import TimeSeriesDatabase

tool_name = "check_opa_fabric"  # our name


# functions:

def get_config(config_file_path, debug=False):
    if os.path.isfile(config_file_path):
        config_file = open(config_file_path, 'r')
        conf = yaml.safe_load(config_file)
        if debug:
            print("conf")
            print(str(conf))
            print("end of conf")
        config_file.close()
        return conf
    else:
        print("Err: No config file found")
        sys.exit(2)


# main daemon class:

class CheckOpaFabricDaemon(Daemon):

    def __init__(self, conf, logger, pidfile='/tmp/opastats.pid', stdin='/dev/null', stdout='/tmp/opastats.stdout', stderr='/tmp/opastats.stdout'):

        Daemon.__init__(self, pidfile, stdin, stdout, stderr)
        self.config = conf
        self.logger = logger
        logger.info(tool_name + " starting at %s", time())

    def run(self):
        self.logger.info("main thread started..")

        # main loop

        i = 0
        ts = TimeSeriesDatabase(1200)  # 1200 second=20min

        while True and int(i) is not int(2):  # two is enough for everyone ^^
            try:
                i = i + 1  # TODO: this is just dummy counter and this should be removed for production

                # main loop logic here
                logger.info("Collecting data from fabric")

                start_time = timeit.default_timer()

                fabric_info = FabricInfoCollector()
                fabric_info_collected_ts = int(time())

                now = timeit.default_timer() - start_time
                logger.debug("t(FabricInfoCollector())= " + str(now))

                logger.info("Processing nodes")

                start_time = timeit.default_timer()

                for node in fabric_info.node2guid:  # provide results for nodes
                    data, icr = FabricChecker.check_node_port_health(node, fabric_info, conf)  # check node, get perf_data and icinga check result

                    if data:
                        ts.append_list(data, fabric_info_collected_ts)  # post performance data into tsdb

                    if icr:  # if we do have Icinga check result:
                        node_fqdn = str(node) + str(conf['node_to_fqdn_suffix'])
                        Icinga.post_icr(conf, icr, "external-poc-OPA-quality", node_fqdn)  # post it to Icinga

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

                now = timeit.default_timer() - start_time

                logger.debug("t(icinga_http_rest)= " + str(now))
                logger.debug("test rate dump - start")
                logger.debug("remote" + str(ts.rate('LocalLinkIntegrityErrors', ['remote', 'co4220'])))
                logger.debug("local" + str(ts.rate('LocalLinkIntegrityErrors', ['local', 'co4220'])))
                logger.debug("related_tags: " + str(ts.get_related_tags('co4220')))
                logger.debug("related_metrics: " + str(ts.get_related_metrics('co4220')))


                # end of main loop logic.
                pass
            except:
                raise
                self.logger.exception('exception: ')

            sleep(3)  # 133 seconds = 2mins+-   #FIXME 30 is not much.  #3 even worse :)

        logger.debug("loops done..")  # print str(ts.tsdb)


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

daemon = CheckOpaFabricDaemon(conf, logger)
daemon.start()

sys.exit(0)  # inbetween there is fork of our process, so we can end this one.
