from icinga import Icinga
import sys
from icinga import IcingaCheckResult

if __name__ == "__main__":
    print "this file should be not executed standalone"
    sys.exit(1)


# static class providing checking of fabric

class FabricChecker:

    @staticmethod
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

    @staticmethod
    def get_error_counters_from_config(conf, debug=False):
        error_counters = {}
        for item in conf['thresholds']:
            counter_name = str(item['counter'])
            error_counters[counter_name] = {}
            error_counters[counter_name]['crit'] = item['crit']  # absolute critical threshold    # TODO: IMO this makes no sense in long term when rate will be working
            error_counters[counter_name]['warn'] = item['warn']  # absolute warning threshold     # TODO: -""-
            error_counters[counter_name]['rate'] = item['warn']  # critical rate                  # TODO: perhaps warning rate could make sense.. But not sure what should be the event/action to be done

        if debug:
            print str(error_counters)

        return error_counters

    @staticmethod
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

    @staticmethod
    def check_port(port_error_counters, error_counters, hide_good=False):

        crit = False
        warn = False
        os = ""

        # LinkQualityIndicator
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkQualityIndicator'], 'LinkQualityIndicator', ['5'], ['4'], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

        # LinkSpeedActive
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkSpeedActive'], 'LinkSpeedActive', ['25Gb'], [], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

        # LinkWidthDnGradeTxActive
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkWidthDnGradeTxActive'], 'LinkWidthDnGradeTxActive', ['4'], [], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

        # LinkWidthDnGradeRxActive
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkWidthDnGradeRxActive'], 'LinkWidthDnGradeRxActive', ['4'], [], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

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

        return crit, warn, os

    @staticmethod
    def check_port_with_perf_data(port_error_counters, error_counters, hide_good=False):

        crit = False
        warn = False
        unknown = False

        os = ""

        perf_data = []

        # LinkQualityIndicator
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkQualityIndicator'], 'LinkQualityIndicator', ['5'], ['4'], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

        # LinkSpeedActive
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkSpeedActive'], 'LinkSpeedActive', ['25Gb'], [], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

        # LinkWidthDnGradeTxActive
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkWidthDnGradeTxActive'], 'LinkWidthDnGradeTxActive', ['4'], [], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

        # LinkWidthDnGradeRxActive
        (rc, message) = FabricChecker.check_indicator(port_error_counters['LinkWidthDnGradeRxActive'], 'LinkWidthDnGradeRxActive', ['4'], [], hide_good)
        (crit, warn, os) = Icinga.process_check_output(crit, warn, os, rc, message)

        # all "simple" err counters - we're checking if number is higher than some threshold.
        for counter in error_counters:

            try:
                value = int(port_error_counters[counter])
            except:
                # we're not able to parse value,  the typical reason is the data are missing, bcs port is down, we'll return unknown flag
                unknown = True
                return (crit, warn, unknown, "", None)

            tags = None
            data_tuple = (None, counter, value, tags)
            perf_data.append(data_tuple)

        return crit, warn, unknown, os, perf_data

    @staticmethod
    def check_node_port_health(node, fabric_info, conf):

        crit = False
        warn = False
        unknown = False

        error_counters = FabricChecker.get_error_counters_from_config(conf)  # counters we want to check including thresholds

        try:
            (r_crit, r_warn, r_unknown, r_os, data_remote) = FabricChecker.check_port_with_perf_data(fabric_info.get_node_remote_port_errors(node), error_counters)
            (l_crit, l_warn, l_unknown, l_os, data_local) = FabricChecker.check_port_with_perf_data(fabric_info.get_node_local_port_errors(node), error_counters)
        except KeyError:
            #    raise  #for debug uncomment
            return None, None

        # process return code:
        if r_crit or l_crit:
            crit = True
        elif r_warn or l_warn:
            warn = True
        elif r_unknown or l_unknown:
            unknown = True

        icr = IcingaCheckResult()

        # header for the output

        if l_crit or l_warn:
            icr.append_string("local port problem")
        if r_crit or r_warn:
            icr.append_string("remote port problem")

        if not (l_crit or l_warn) and not (r_crit or r_warn) and not (r_unknown or l_unknown):
            icr.append_string("[OK] - both sides of link are OK")

        if unknown:
            icr.append_string("[UNKNOWN] - one of the ports is unreachable..")

        icr.append_new_line()
        icr.append_string(Icinga.create_local_port_status_string(l_os))  # local port
        icr.append_string(Icinga.create_remote_port_status_string(r_os, fabric_info.get_node_remote_port_nodedesc(node), fabric_info.get_node_remote_port_portnr(node)))  # remote port.

        icr.status_code = Icinga.STATE_OK

        if warn:
            icr.status_code = Icinga.STATE_WARNING
        if crit:
            icr.status_code = Icinga.STATE_CRITICAL
        if unknown:
            icr.status_code = Icinga.STATE_UNKNOWN

        new_data = FabricChecker.build_data_bundle(data_local, data_remote, node)

        return new_data, icr

    @staticmethod
    def build_data_bundle(data_local, data_remote, node):

        """
        add node tag to the data, tag local and remote port..
        """

        new_data = []
        if data_local:  # data can be also empty = dead port, etc. then we'll return none.
            for item in data_local:
                (t_time, t_metric, t_value, t_tags) = item
                t_tags = [node, 'local']  # tag was empty, let's add tag
                new_data.append((t_time, t_metric, t_value, t_tags))
        if data_remote:
            for item in data_remote:
                (t_time, t_metric, t_value, t_tags) = item
                t_tags = [node, 'remote']  # tag was empty, let's add tag
                new_data.append((t_time, t_metric, t_value, t_tags))

        if len(new_data) > 1:
            return new_data
        else:
            return None

    @staticmethod
    def check_switch_interswitch_links_count(switch, switch_icinga_hostname, expected_port_count, fabric_info, conf):
        oc = Icinga.STATE_OK
        os = ""

        portcount = fabric_info.get_switch_inter_switch_port_count(switch)

        if int(expected_port_count) != int(portcount):
            os = "[WARNING] different (" + str(portcount) + ") than expected (" + str(conf['top_level_switch_downlinks_count']) + ") downlinks port count found on this switch."
            oc = Icinga.STATE_WARNING
        else:
            os = "[OK] expected downlinks port count found (" + str(portcount) + ") there on " + str(switch)
            oc = Icinga.STATE_OK

        Icinga.post_check_result(conf, conf['api_host'], int(conf['api_port']), switch_icinga_hostname, "external-poc-downlink-port-count", int(oc), str(os), conf['check_source'])

    @staticmethod
    def check_switch_ports(switch, switch_icinga_hostname, fabric_info, conf):
        os_links = ""
        oc_links = Icinga.STATE_OK
        warn = False
        crit = False

        error_counters = FabricChecker.get_error_counters_from_config(conf)

        try:

            for port in fabric_info.inter_switch_links[switch]:
                try:
                    (r_crit, r_warn, r_os) = FabricChecker.check_port(fabric_info.get_switch_remote_port_errors(switch, port), error_counters, hide_good=True)  # we don't want to see good ports, bcs. there is too much of them
                    (l_crit, l_warn, l_os) = FabricChecker.check_port(fabric_info.get_switch_local_port_errors(switch, port), error_counters, hide_good=True)

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
                    print("err: key missing")
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

            Icinga.post_check_result(conf, conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", int(oc_links), str(os_links), conf['check_source'], debug=False)
        except KeyError:
            # this exception means there is port down on the switch. This is not unusual state.
            Icinga.post_check_result(conf, conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", 3, "switch unreachable", conf['check_source'], debug=False)
