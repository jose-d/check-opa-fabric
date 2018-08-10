import requests  # to be able send passive checks result to Icinga2 API
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # to be able to modify warning for SSL

if __name__ == "__main__":
    print "this file should be not executed standalone"
    sys.exit(1)


class IcingaCheckResult():

    def __init__(self):
        self.text = ""
        self.status_code = None

    def append_string(self, string):
        self.text = str(self.text) + str(string)

    def append_new_line(self):
        self.append_string('\n')

    def prepend_string(self, string):
        self.text = str(string) + str(self.text)


class Icinga():
    # constants for Icinga(Nagios) return codes:

    STATE_OK = 0
    STATE_WARNING = 1
    STATE_CRITICAL = 2
    STATE_UNKNOWN = 3
    STATE_DEPENDENT = 4

    @staticmethod
    def prepare_session(http_user, http_password):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # disable SSL warning

        session = requests.Session()  # let's use session - it will speed-up the POST-ing, and also it will let us create cleaner code. Little bit.
        session.trust_env = False  # we don't want any variables from env.
        session.auth = (http_user, http_password)  # auth credentials
        session.verify = False  # verify SSL?

        return session

    @staticmethod
    def post_icr(conf, icr, check_name, host):
        return Icinga.post_check_result(conf, conf['api_host'], int(conf['api_port']), host, check_name, int(icr.status_code), str(icr.text), conf['check_source'])

    @staticmethod
    def post_check_result(conf, icinga_server, icinga_server_port, host, check, status, output, source, debug=False):
        if debug: print("posting..")

        url = 'https://' + str(icinga_server) + ":" + str(icinga_server_port) + '/v1/actions/process-check-result?service=' + str(host) + '!' + str(check)

        session = Icinga.prepare_session(conf['api_user'], conf['api_pass'])

        try:
            r = session.post(url, json={'exit_status': str(status), 'plugin_output': str(output), 'check_source': str(source)}, headers={'Accept': 'application/json', 'Connection': 'close'})
            if debug: print(str(r))
            if r.status_code == 200:
                return True
            else:
                return False
        except:
            if debug: raise
            return False

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
    def create_local_port_status_string(port_counters=None):
        os = ""

        os = str(os) + "<p>"
        os = str(os) + "<b>Local port summary</b>"
        os = str(os) + str(port_counters)
        os = str(os) + '</p>'

        return os

    @staticmethod
    def create_remote_port_status_string(port_counters=None, remote_port_nodedesc=None, remote_port_portnr=None):
        os = ""

        os = str(os) + "<p>"
        os = str(os) + "<b>Remote port ( nodedesc: " + str(remote_port_nodedesc) + ", port: " + str(remote_port_portnr) + " ) summary</b>"
        os = str(os) + str(port_counters)
        os = str(os) + "</p>"

        return os
