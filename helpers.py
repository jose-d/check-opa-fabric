from time import gmtime, strftime
import subprocess
import threading
import timeit
from urlparse import urlparse  # URL validation


def info_message(message):
    print strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\t" + message


def error_message(message):
    print bcolors.FAIL + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\t" + message + bcolors.ENDC


def runtime_info_message(message, start_time):
    now = timeit.default_timer() - start_time
    print "[" + str("0%.9f" % now) + "] " + message


def uri_validator(x):
    try:
        result = urlparse(x)
        return result.scheme and result.netloc and result.path
    except:
        return False


def parse_node_from_nodedesc(node_desc):
    return node_desc.split(' ')[0].strip()


class bcolors():
    # constants for colors in BASH terminal:

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None
        self.stdout = None
        self.stderr = None
        self.rc = None

    def run(self, timeout):
        def target():
            self.process = subprocess.Popen(self.cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.stdout, self.stderr = self.process.communicate()
            self.rc = self.process.wait()

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            print 'Command.run(): timeout: terminating process'
            self.process.terminate()
            thread.join()
            self.rc = 999

        return (self.rc, self.stdout, self.stderr)


if __name__ == "__main__":
    print "this file should be not executed standalone"
    sys.exit(1)
