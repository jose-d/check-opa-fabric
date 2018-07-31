from icinga import Icinga


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
            error_counters[counter_name]['crit'] = item['crit']
            error_counters[counter_name]['warn'] = item['warn']

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

        return (crit, warn, os)

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

            Icinga.post_check_result(conf, conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", int(oc_links), str(os_links), conf['check_source'], debug=False)
        except KeyError:
            # this exception means there is port down on the switch. This is not unusual state.
            Icinga.post_check_result(conf, conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname), "external-poc-downlink-port-health", 3, "switch unreachable", conf['check_source'], debug=False)
