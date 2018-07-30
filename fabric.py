import sys
import csv  # to parse CSV from intel OPA tools
import re  # regular expression parsing to detect the opareport link

from helpers import *


if __name__ == "__main__":
    print "this file should be not executed standalone"
    sys.exit(1)

class FabricInfoCollector:

    @staticmethod
    def __parse_node_from_nodedesc(node_desc):
        return node_desc.split(' ')[0].strip()

    def __init__(self):

        #data collection from fabric:

        command_string = 'opaextractlids -q -F nodetype:FI'
        cmd = Command(command_string)
        (self.rc_oel, self.stdout_oel, self.stderr_oel) = cmd.run(15)  # 15 sec is enough for everyone. :)

        command_string = 'opaextracterror -q'
        cmd = Command(command_string)
        (self.rc_oee, self.stdout_oee, self.stderr_oee) = cmd.run(30)  # 30 sec is enough for everyone. :)

        command_string = 'opareport -q -o links'
        cmd = Command(command_string)
        (self.rc_orl, self.stdout_orl, self.stderr_orl) = cmd.run(30)  # 30 sec is enough for everyone. :)

        command_string = 'opareport -o nodes -d 1'
        cmd = Command(command_string)
        (self.rc_orn, self.stdout_orn, self.stderr_orn) = cmd.run(30)  # 30 sec is enough for everyone. :)

        # .
        # ..parse the opaextractLID - this will provide us two following data structures:
        # .

        self.fabric = {}        # fabric[SystemImageGUID]['opa_extract_lids'] = ['SystemImageGUID', 'PortNum', 'NodeType', 'NodeDesc', 'LID']
        self.node2guid = {}     # node_desc -> SystemImageGUID

        # as we have the data just for "FI" nodes in the fabric, both structures are switches-free ..

        try:
            opa_extract_lids_csv_reader = csv.reader(self.stdout_oel.splitlines(), delimiter=';')
        except:
            print "ERR: csv parse orror in opaextractlids output."
            sys.exit(int(Icinga.STATE_UNKNOWN))

        csv_headers = ['SystemImageGUID', 'PortNum', 'NodeType', 'NodeDesc', 'LID']  # there is no CSV header so we'll create it manually..
        opa_extract_lids_csv_columns_count = int(len(csv_headers))

        for row in opa_extract_lids_csv_reader:  # now iterate over lines and create dictionary from every line
            guid = row[0]
            if not guid in self.fabric: self.fabric[guid] = {}  # create key

            oel = {}
            for column_number in range(0, opa_extract_lids_csv_columns_count):
                key = csv_headers[column_number]
                value = row[column_number]
                oel[key] = value
            self.fabric[guid]['opa_extract_lids'] = oel
            self.node2guid[FabricInfoCollector.__parse_node_from_nodedesc(row[3])] = guid

        # .
        # ..parse the data from opaextract errors (will produce self.opa_errors)
        # .

        try:
            opa_extract_error_csv_reader = csv.reader(self.stdout_oee.splitlines(), delimiter=';')
        except:
            print "ERR: csv parse orror in opaextracterror output."
            sys.exit(int(Icinga.STATE_UNKNOWN))

        self.opa_errors = {}

        # this is in the CSV variable now:
        # ['NodeDesc', 'SystemImageGUID', 'PortNum', 'LinkSpeedActive', 'LinkWidthDnGradeTxActive', 'LinkWidthDnGradeRxActive', 'LinkQualityIndicator', 'RcvSwitchRelayErrors', 'LocalLinkIntegrityErrors', 'RcvErrors', 'ExcessiveBufferOverruns', 'FMConfigErrors', 'LinkErrorRecovery', 'LinkDowned', 'UncorrectableErrors', 'RcvConstraintErrors', 'XmitConstraintErrors']
        # ['co1195 hfi1_0', '0x001175010108866d', '1', '25Gb', '4', '4', '5', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0']

        # parse headers now:

        csv_headers = opa_extract_error_csv_reader.next()  # headers are the first line in CSV
        opa_extract_error_csv_columns_count = int(len(csv_headers))

        for row in opa_extract_error_csv_reader:  # now iterate over lines and create dictionary from every line
            guid = row[1]
            port_nr = row[2]
            node_desc = row[0]
            oee = {}

            if not guid in self.fabric:
                self.fabric[guid] = {}  # create key it it's not there..
            if not str(FabricInfoCollector.__parse_node_from_nodedesc(row[0])) in self.node2guid:
                self.node2guid[str(FabricInfoCollector.__parse_node_from_nodedesc(row[0]))] = guid  # create key if it's not there..

            for column_number in range(0, opa_extract_error_csv_columns_count):
                oee[csv_headers[column_number]] = row[column_number]

                self.fabric[guid]['opa_extract_error'] = oee

            if node_desc not in self.opa_errors:
                self.opa_errors[node_desc] = {}
            if port_nr not in self.opa_errors[node_desc]:
                self.opa_errors[node_desc][int(port_nr)] = oee

        # .
        # and parse the top-level-fabric switches, their nodeguid and image guid
        # we look for following pattern:
        #
        #     Name: top01
        #         NodeGUID: 0x00117501020c4752 Type: SW
        #         Ports: 48 PartitionCap: 32 SystemImageGuid: 0x00117501ff0c4752
        #

        # here: conf['top_level_switch_name_pattern'] is string "top" - as a top level switch pattern:

        name_line_pattern = re.compile("\s+Name:\s+top\w+")
        node_guid_pattern = re.compile("\s+NodeGUID:\s+\w{16}")
        system_image_guid_pattern = re.compile("SystemImageGuid:")

        top_level_switch_name = None
        top_level_switch_node_guid = None
        top_level_switch_image_guid = None

        self.top_level_switches = {}

        for line in self.stdout_orn.splitlines():
            if not top_level_switch_name and not top_level_switch_node_guid and not top_level_switch_image_guid:
                # we're looking for first line:
                if name_line_pattern.search(str(line)):
                    # name matched
                    top_level_switch_name = str(line.split()[1]).strip()
                    continue
            elif top_level_switch_name and not top_level_switch_node_guid and not top_level_switch_image_guid:
                # we have switch name, we're looking for second line - the one with NodeGUID:
                if node_guid_pattern.search(str(line)):
                    # matched, good
                    top_level_switch_node_guid = str(str(line).strip().split(' ')[1])
                    continue
                else:
                    top_level_switch_name = None  # some mistake, broken format etc.
                    continue
            elif top_level_switch_name and top_level_switch_node_guid and not top_level_switch_image_guid:
                # we have switch name, we have node guid, we're looking for image guid:
                if system_image_guid_pattern.search(str(line)):
                    # matched, good
                    top_level_switch_image_guid = str(line.split()[5]).strip()
                    # now we have everyhing
                    self.top_level_switches[top_level_switch_name] = (top_level_switch_node_guid, top_level_switch_image_guid)
                    # reset the loop variables:
                    top_level_switch_node_guid = None
                    top_level_switch_image_guid = None
                    top_level_switch_name = None
                    continue
                else:
                    top_level_switch_name = None  # some mistake, broken format, etc. lets reset and start from the 0
                    top_level_switch_node_guid = None
                    continue

        # parse the links between switches

        # 100g 0x00117501020c3864  25 SW   top06
        # <->  0x001175010277954a   8 SW   opa4 L121B

        first_line_pattern = re.compile("^\d+g\s+0x\w{16}\s+\d+\s+SW")
        second_line_pattern = re.compile("^<->\s+0x\w{16}\s+\d+\s+SW")

        src_nodedesc = None
        src_portnr = None
        dest_nodedesc = None
        dest_portnr = None

        self.inter_switch_links = {}

        for row in self.stdout_orl.splitlines():
            if not src_nodedesc and not src_portnr and not dest_nodedesc and not dest_portnr:
                if first_line_pattern.search(str(row)):
                    row_splitted = row.split()
                    src_portnr = str(row_splitted[2]).strip()
                    src_nodedesc = ""
                    for row_splitted_index in range(4, len(row_splitted)):
                        src_nodedesc = src_nodedesc + row_splitted[row_splitted_index] + " "
                    src_nodedesc = src_nodedesc.strip()
                    continue

            if src_nodedesc and src_portnr and not dest_nodedesc and not dest_portnr:
                if second_line_pattern.search(str(row)):
                    row_splitted = row.split()
                    dest_portnr = str(row_splitted[2]).strip()
                    dest_nodedesc = ""
                    for row_splitted_index in range(4, len(row_splitted)):
                        dest_nodedesc = dest_nodedesc + row_splitted[row_splitted_index] + " "
                    dest_nodedesc = dest_nodedesc.strip()
                    # now we have what we want
                    if src_nodedesc not in self.inter_switch_links:
                        self.inter_switch_links[src_nodedesc] = {}
                    if dest_nodedesc not in self.inter_switch_links:
                        self.inter_switch_links[dest_nodedesc] = {}

                    self.inter_switch_links[src_nodedesc][src_portnr] = (dest_nodedesc, dest_portnr)  # save the result into structure
                    self.inter_switch_links[dest_nodedesc][dest_portnr] = (src_nodedesc, src_portnr)  # and the reverse path too.

                    # reset the state
                    src_nodedesc = None
                    src_portnr = None
                    dest_nodedesc = None
                    dest_portnr = None
                    continue

                else:
                    # reset the state too as most likely broken input or smth like this..
                    src_nodedesc = None
                    src_portnr = None
                    dest_nodedesc = None
                    dest_portnr = None
                    continue

        # and parse the opareport links now - stdout_orl should look like:

        # Link Summary

        # 5967 Links in Fabric:
        # Rate NodeGUID          Port Type Name
        # 100g 0x001175010108866d   1 FI   co1195 hfi1_0
        # <->  0x00117501027ab700   3 SW   opa1 L113B
        # ...
        # 100g 0x001175010277aef2  39 SW   opa2 S201B
        # <->  0x0011750102783f83  39 SW   opa2 L121A
        # -------------------------------------------------------------------------------

        node_pattern = re.compile("^\d+g\s+0x\w{16}\s+\d+\s+FI")  # search for 100g 0x001175010108866d   1 FI   co1195 hfi1_0
        ds_pattern = re.compile("^<->\s+0x\w{16}\s+\d+\s+SW")  # same as above but different. :)

        node_found = False

        # reset variables:

        node_guid = None

        for row in self.stdout_orl.splitlines():

            if node_found:  # we expect line describing the director switch line:
                if ds_pattern.search(str(row)):
                    row_splitted = row.split()  # smth like: ['<->', '0x00117501027aaa65', '9', 'SW', 'opa3', 'L112B']

                    switch_guid = row_splitted[1]
                    switch_port = row_splitted[2]

                    # the rest of line will be nodedesc
                    switch_nodedesc = ""
                    for row_splitted_index in range(4, len(row_splitted)):
                        switch_nodedesc = switch_nodedesc + row_splitted[row_splitted_index] + " "

                    # print "link info: node_guid: " + str(node_guid) + " (" + str(node_nodedesc) + ") switch guid: " + str(switch_guid) + ", port: " + str(switch_port) + ", desc: " + str(switch_nodedesc)
                    if node_guid in self.fabric:
                        self.fabric[node_guid]['nb'] = (switch_guid, switch_port, switch_nodedesc)  # the switch guid is NODEGUID - not PORT_GUID (!) :(
                    else:
                        print "err: node is missing in fabric, strange error."

                    node_found = False
                else:
                    node_found = False
            else:
                if node_pattern.search(str(row)):
                    row_splitted = row.split()  # smth like: ['100g', '0x001175010108866d', '1', 'FI', 'co1195', 'hfi1_0']
                    node_guid = row_splitted[1]

                    node_nodedesc = ""
                    for row_splitted_index in range(4, len(row_splitted)):
                        node_nodedesc = node_nodedesc + row_splitted[row_splitted_index] + " "
                    node_found = True
                else:
                    node_guid = None
                    node_found = False

        # and parse the NodeGuid to SystemImageGuid
        # we look for following patterns:
        # NodeGUID: 0x00117501027bc7c6 Type: SW
        # Ports: 48 PartitionCap: 32 SystemImageGuid: 0x00117501fb000485

        node_guid_pattern = re.compile("\s+NodeGUID:\s\w{16}")
        system_image_guid_pattern = re.compile("SystemImageGuid:")

        node_guid_matched = False
        self.node_guid_to_system_image_guid = {}

        for line in self.stdout_orn.splitlines():
            if not node_guid_matched:
                if node_guid_pattern.search(str(line)) and "SW" in str(line):
                    line_splitted = line.split()
                    node_guid_matched = True
                    node_guid = line_splitted[1]
            else:
                if system_image_guid_pattern.search(str(line)):
                    line_splitted = line.split()
                    system_image_guid = line_splitted[5]
                    self.node_guid_to_system_image_guid[node_guid] = system_image_guid
                    node_guid_matched = False
                else:
                    node_guid_matched = False






