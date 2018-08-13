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
import icinga
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

    def __init__(self, conf, logger, pidfile='/tmp/opastats.pid', stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):

        Daemon.__init__(self, pidfile, stdin, stdout, stderr)
        self.config = conf
        self.logger = logger
        logger.info(tool_name + " starting at %s", time())

    def run(self):
        self.logger.info("main thread started..")

        # main loop

        i = 0
        ts = TimeSeriesDatabase(1200)  # 1200 second=20min
        error_counters = FabricChecker.get_error_counters_from_config(conf)  # parse counters and their thresholds:

        while True and int(i) is not int(100):  # two is enough for everyone ^^
            try:
                i = i + 1  # TODO: this is just dummy counter to limit the amount of daemon loops and should be removed for production including related logic.

                logger.info("i:" + str(i))

                # main loop logic here
                logger.info("Collecting data from fabric")

                start_time = timeit.default_timer()

                fabric_info = FabricInfoCollector()
                fabric_info_collected_ts = int(time())

                now = timeit.default_timer() - start_time
                logger.debug("t(FabricInfoCollector())= " + str(now))

                logger.info("Processing nodes")

                for node in fabric_info.node2guid:  # provide results for nodes
                    data, icr = FabricChecker.check_node_port_health(node, fabric_info, conf)  # type: (object, IcingaCheckResult)

                    if data:
                        ts.append_list(data, fabric_info_collected_ts)  # post performance data into tsdb

                        # analyze the performance counters:
                        metrics = ts.get_related_metrics(node)
                        # metrics = ["LocalLinkIntegrityErrors", ]
                        sides = ["local", "remote"]
                        html_table = None  # type: String
                        for metric in metrics:
                            for side in sides:
                                value = ts.rate(metric, [side, node])  # will return tuple like: (hourly-rate, first value, last value, diff in secs)
                                rate = value[0]
                                if rate > error_counters[metric]['rate']:
                                    print (str(node) + "," + str(metric) + ":" + str(value) + "/" + str(error_counters[metric]['rate']))
                                    if not html_table:
                                        html_table = "<table>"
                                    html_table = str(html_table) + "<tr><td>" + str(metric) + "(" + str(side) + ")</td><td>" + str(rate) + " /sec" + "" + "</td></tr>"
                        if html_table:
                            html_table = str(html_table) + "</table>"
                            icr.append_string(html_table)

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

                # end of main loop logic.
                pass
            except:
                raise
                self.logger.exception('exception: ')

            sleep(3)  # 133 seconds = 2mins+-   #FIXME 30 is not much.  #3 even worse :)

        logger.debug("loops done..")  # print str(ts.tsdb)
        exit(0)


# main: ----------------------------------------------------------------------------------------------------------------

# get config from config file - the config file path is now hardcoded.. :(

pathname = os.path.dirname(sys.argv[0])
script_directory = os.path.abspath(pathname)  # TODO: for debugging this is not working, as we're starting the project from temp directory
config_directory = script_directory  # TODO: so for production,
config_directory = '/usr/local/monitoring'  # TODO: uncomment this line :) when switching to production.

config_file_path = os.path.abspath(str(config_directory) + "/ext_check_opa_fabric.conf")
conf = get_config(config_file_path)

# setup logging:

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler = logging.handlers.RotatingFileHandler(conf['logger_logfile'], maxBytes=20 * 1024 * 1024, backupCount=5)
handler.setFormatter(formatter)
logger = logging.getLogger(tool_name)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)  # could be done better. for example with some config :)

logger.info("logging setup done.")

# start daemon:

daemon = CheckOpaFabricDaemon(conf, logger, pidfile=conf['daemon_pid'], stdout=conf['daemon_stdout'], stderr=conf['daemon_stderr'])
daemon.start()

logger.info("daemon started, exiting the main() thread")

sys.exit(0)  # inbetween there is fork of our process, so we can end this one.
