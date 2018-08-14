import sys
import logging
from collections import deque

if __name__ == "__main__":
    print("this file should be not executed standalone")
    sys.exit(1)


class TimeSeriesOpaDataItem:
    timestamp = None  # type: int
    remote = None  # type: int
    port = None  # type: int
    host = None  # type: str
    metric_value = None  # type: int
    metric_name = None  # type: str

    def __init__(self, metric_name=None, metric_value=None, host=None, port=None, remote=None, timestamp=None):
        """

        :type timestamp: int
        :type remote: int
        :type port: int
        :type host: str
        :type metric_value: int
        :type metric_name: str
        """

        self.timestamp = timestamp
        self.metric_name = metric_name
        self.metric_value = metric_value
        self.host = host
        self.port = port
        self.remote = remote

    def __repr__(self):
        return_string = "tsdb.TimeSeriesOpaDataItem instance __repr__:\n"
        return_string = return_string + "timestamp:\t" + str(self.timestamp) + '\n'
        return_string = return_string + "metric_name:\t" + str(self.metric_name) + '\n'
        return_string = return_string + "metric_value:\t" + str(self.metric_value) + '\n'
        return_string = return_string + "host:\t\t" + str(self.host) + '\n'
        return_string = return_string + "port:\t\t" + str(self.port) + '\n'
        return_string = return_string + "remote:\t\t" + str(self.remote) + '\n'

        return str(return_string)


class TimeSeriesDatabase:
    logger = None  # type: logging.Logger
    depth = None  # type: int
    node_desc_dictionary = None  # type: dict

    def __init__(self, logger=None, depth=10):
        """

        :type depth: int
        :type logger: logging.Logger
        """

        self.logger = logger
        self.depth = depth  # depth of TSdb = amount of items
        self.node_desc_dictionary = {}

    def __sizeof__(self):
        return sys.getsizeof(self.depth) + sys.getsizeof(self.node_desc_dictionary)

    def get_node_port_metric_names(self, node, port):
        """

        :type port: int
        :type node: str
        """

        if node not in self.node_desc_dictionary:
            return None  # we have no data about node

        metric_names = []
        sides = [0, 1]

        for side in sides:
            if side in self.node_desc_dictionary[node]:
                if port in self.node_desc_dictionary[node][side]:
                    for metric in self.node_desc_dictionary[node][side][port]:
                        if metric not in metric_names:
                            metric_names.append(metric)

        return metric_names

    @staticmethod
    def create_tuple_from_item(item):
        """

        :type item: TimeSeriesOpaDataItem
        """

        return tuple((item.timestamp, item.metric_value))

    def _check_and_create_data_structures_for_item(self, item):
        """

        :type item: TimeSeriesOpaDataItem
        """

        # data structure example: self.node_desc_dictionary['co1234']['0'.. local/ '1'..remote]['0'..portnr]['LinkErrorsWhatever']

        if item.host not in self.node_desc_dictionary:
            self.node_desc_dictionary[item.host] = {}  # dict for local|remote

        if item.remote not in self.node_desc_dictionary[item.host]:
            self.node_desc_dictionary[item.host][item.remote] = {}  # dict for portNr

        if item.port not in self.node_desc_dictionary[item.host][item.remote]:
            self.node_desc_dictionary[item.host][item.remote][item.port] = {}  # dict for metric name

        if item.metric_name not in self.node_desc_dictionary[item.host][item.remote][item.port]:
            self.node_desc_dictionary[item.host][item.remote][item.port][item.metric_name] = deque()  # and finally, insert the queue

    def get_rate(self, host, remote, port, metric_name):
        """

        :type metric_name: str
        :type port: int
        :type remote: int
        :type host: str
        """

        dt = self.get_time_difference_between_youngest_and_oldest_data(host, remote, port, metric_name)

        if dt == 0:
            return 0

        dv = self.get_value_difference_between_youngest_and_oldest_data(host, remote, port, metric_name)

        return float(dv / dt)

    def get_value_difference_between_youngest_and_oldest_data(self, host, remote, port, metric_name):
        """

        :type metric_name: str
        :type port: int
        :type remote: int
        :type host: str
        """
        diff = int(self.node_desc_dictionary[host][remote][port][metric_name][-1][1] - self.node_desc_dictionary[host][remote][port][metric_name][0][1])
        if diff < 0:
            self.logger.warning("value diff is in negative numbers. Possible overflow happened.")
            return 0

        return diff

    def get_time_difference_between_youngest_and_oldest_data(self, host, remote, port, metric_name):
        """

        :type metric_name: str
        :type port: int
        :type remote: int
        :type host: str
        """
        diff = int(self.node_desc_dictionary[host][remote][port][metric_name][-1][0] - self.node_desc_dictionary[host][remote][port][metric_name][0][0])
        if diff < 0:
            self.logger.warning("time diff is in negative numbers. Possible overflow happened.")
            return 0

        return diff

    def append_list(self, list_of_data, timestamp):
        """

        :type timestamp: int
        :type list_of_data: list
        """

        for list_item in list_of_data:  # that's tuple of values counter,value,node, port, remote
            item = TimeSeriesOpaDataItem(list_item[0], list_item[1], list_item[2], list_item[3], list_item[4], timestamp)  # (metric_name,metric_value,host,port,remote,timestamp)
            self.append(item)

    def _append_into_datastruct(self, item):
        """

        :type item: TimeSeriesOpaDataItem
        """

        self.node_desc_dictionary[item.host][item.remote][item.port][item.metric_name].append(TimeSeriesDatabase.create_tuple_from_item(item))

    def append(self, item):
        """

        :type item: TimeSeriesOpaDataItem
        """

        self._check_and_create_data_structures_for_item(item)
        self._append_into_datastruct(item)

    def cleanup(self):
        pass
