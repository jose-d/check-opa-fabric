#!/usr/bin/python

# check opa fabric
#

# Credits:
#
# Scripting: Josef Dvoracek


import subprocess,threading
import os.path
import sys
import platform

import timeit
from time import gmtime, strftime
from subprocess import PIPE, Popen,call

import argparse	#to parse arguments, yeah
import csv	#to parse CSV from intel OPA tools
import requests	#to be able send passive checks result to Icinga2 API
from requests.packages.urllib3.exceptions import InsecureRequestWarning	#to be able to modify warning for SSL

from urlparse import urlparse	#URL validation

import yaml 			#config file parsing

import re			#regular expression parsing to detect the opareport link

#check config:

#functions:



def info_message(message):
  print strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\t" + message

def error_message(message):
  print bcolors.FAIL + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\t" + message + bcolors.ENDC

def parse_int_value_from_ipmitool_line(ipmitool_line):
  try:
    i=int(str(ipmitool_line).split('|')[1].strip().split('.')[0])
    return i
  except:
    print "ERR in parse_int_value_from_ipmitool_line: Error when parsing Integer value from line " + str(ipmitool_line)
    sys.exit(int(Icinga.STATE_UNKNOWN))

def prepare_session(httpuser,httppassword):

  requests.packages.urllib3.disable_warnings(InsecureRequestWarning)      #disable SSL warning

  session = requests.Session()    #let's use session - it will speed-up the POST-ing, and also it will let us create cleaner code. Little bit.
  session.trust_env = False       #we don't want any variables from env.
  session.auth= ('externalchecks', 'externalchecks')      #auth credentials
  session.verify=False    #verify SSL?

  return session

def post_check_result(icingaserver,icingaserverport,host,check,status,output,source,debug=False):

  if debug: print "posting.."

  URL='https://' + str(icingaserver) + ":" + str(icingaserverport) + '/v1/actions/process-check-result?service=' + str(host) + '!' + str(check)

  try:
    r=session.post(URL,json={'exit_status':str(status),'plugin_output':str(output),'check_source':str(source)},headers={'Accept': 'application/json','Connection':'close'})
    if debug: print str(r)
    if r.status_code == 200:
      return True
    else:
      return False
  except:
    if debug: raise
    return False
  
  if debug: print "posted."

def uri_validator(x):
  try:
    result = urlparse(x)
    return result.scheme and result.netloc and result.path
  except:
    return False

def check_indicator(value,name,ok_values,warning_values,hide_good=False):

  crit=False
  warn=False

  if str(value) in ok_values:
    if hide_good:
      message=""
      pass
    else:
      message="[OK] indicator " + str(name) + " has reference value, " + str(value) + "/" + str(ok_values) + "."
  elif str(value) in warning_values:
    message="[WARNING] indicator " + str(name) + " is at warning level, " + str(value) + "/" + str(ok_values) + "."
    warn=True
  else:
    message="[CRITICAL] indicator " + str(name) + " is at critical level, " + str(value) + "/" + str(ok_values) + "."
    crit=True

  if crit: rc=2
  elif warn: rc=1
  else: rc=0

  return (rc,message)

def process_check_output(crit,warn,os,rc,message):

  l_crit=crit
  l_warn=warn
  l_os=os
  
  if rc==2: l_crit=True
  elif rc==1: l_warn=True
  l_os=str(l_os)+'<p>'+str(message)+'</p>'

  return (l_crit,l_warn,l_os)

def parse_node_from_nodedesc(node_desc):
  return node_desc.split(' ')[0].strip()

def check_port(port_error_counters,hide_good=False):

  crit=False
  warn=False
  os=""

  #LinkQualityIndicator
  (rc,message) = check_indicator(port_error_counters['LinkQualityIndicator'],'LinkQualityIndicator',['5'],['4'],hide_good)
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkSpeedActive
  (rc,message) = check_indicator(port_error_counters['LinkSpeedActive'],'LinkSpeedActive',['25Gb'],[],hide_good)
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkWidthDnGradeTxActive
  (rc,message) = check_indicator(port_error_counters['LinkWidthDnGradeTxActive'],'LinkWidthDnGradeTxActive',['4'],[],hide_good)
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkWidthDnGradeRxActive
  (rc,message) = check_indicator(port_error_counters['LinkWidthDnGradeRxActive'],'LinkWidthDnGradeRxActive',['4'],[],hide_good)
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #all "simple" err counters - we're chacking if number is higher than some threshold.
  for counter in error_counters:
    bad=False
    rs="[OK]"
    value=int(port_error_counters[counter])
    stats.save_stat(fabric,node,value,counter)
    if value>error_counters[counter]['warn']:
      warn=True
      bad=True
      rs="[WARNING]"
    if value>error_counters[counter]['crit']:
      bad=True
      crit=True
      rs="[CRITICAL]"
    if bad or not hide_good:
      os = os + '<p>' + str(rs) + ":" + str(counter) + " " + str(value) + "</p>"

  return (crit,warn,os)

def runtime_info_message(message,start_time):
    now = timeit.default_timer() - start_time
    print "[" + str("0%.9f" % now) + "] " + message

def check_switch_ports(switch,switch_icinga_hostname):

  os_links = ""
  oc_links = 0
  warn = False
  crit = False

  try:

    for port in inter_switch_links[switch]:
      try:
        local_errors = opa_errors[switch][int(port)]

        remote_switch_nodedesc = inter_switch_links[switch][port][0]
        remote_switch_portnr = inter_switch_links[switch][port][1]
        remote_errors = opa_errors[remote_switch_nodedesc][int(remote_switch_portnr)]

        (r_crit, r_warn, r_os) = check_port(remote_errors, hide_good=True)  # we don't want to see good ports, bcs. there is too much of them
        (l_crit, l_warn, l_os) = check_port(local_errors, hide_good=True)

        if r_crit or l_crit:
          crit = True
        if r_warn or l_warn:
          warn = True

        if l_crit or l_warn:
          os_links = str(os_links) + "<p><b> local port " + str(port) + " is not healthy: </b></p>"
          os_links = str(os_links) + str(l_os)

        if r_crit or r_warn:
          os_links = str(os_links) + "<p><b> remote port connected to port " + str(port) + ", " + str(remote_switch_nodedesc) + " is not healthy: </b></p>"
          os_links = str(os_links) + str(r_os)

      except KeyError:
        print "err: key missing"
        raise
        pass

    if crit:
      oc_links = 2
      os_links = "[CRITICAL] - problems found on switch ports \n" + str(os_links)
    elif warn:
      oc_links = 1
      os_links = "[WARNING] - problem found on switch ports \n" + str(os_links)
    else:
      os_links = "[OK] - switch ports are OK \n" + str(os_links)

    result = post_check_result(conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname),"external-poc-downlink-port-health", int(oc_links), str(os_links), conf['check_source'],debug=False)
  except KeyError:
    result = post_check_result(conf['api_host'], int(conf['api_port']), str(switch_icinga_hostname),"external-poc-downlink-port-health", 3, "switch unreachable", conf['check_source'],debug=False)



class Stats():

  def __init__(self):
    self.stats={}

  def save_stat(self,fabric,node,value,metricname):
    if metricname not in self.stats:	#if not yet there, we will define default values
      self.stats[metricname]={}
      self.stats[metricname]['min']=int(+9999)
      self.stats[metricname]['max']=int(-9999)

    if int(value) > int(self.stats[metricname]['max']): #if bigger than maximum, save it as new maximum
      self.stats[metricname]['max'] = value
    elif int(value) < int(self.stats[metricname]['min']):	#if smaller than minimum, save it as new minimum
      self.stats[metricname]['min'] = value

  def __str__(self):
    return "stats (dummy _str_ function..)\n" + str(self.stats) + "end of stats\n"

class Icinga():
  STATE_OK=0
  STATE_WARNING=1
  STATE_CRITICAL=2
  STATE_UNKNOWN=3
  STATE_DEPENDENT=4

class bcolors():
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
      self.process = subprocess.Popen(self.cmd.split(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
      self.stdout,self.stderr = self.process.communicate()
      self.rc=self.process.wait()

    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
      print 'Command.run(): timeout: terminating process'
      self.process.terminate()
      thread.join()
      self.rc=999

    return (self.rc,self.stdout,self.stderr)

# main: ----------------------------------------------------------------------------------------------------------------

start_time = timeit.default_timer()

# get config from config file - the config file path is now hardcoded.. :(

configpath = os.path.abspath("/usr/local/monitoring/ext_check_opa_fabric.conf")

debug=False

if os.path.isfile(configpath):
  conffile = open(configpath,'r')
  conf = yaml.safe_load(conffile)
  if debug:
    print "conf"
    print str(conf)
    print "end of conf"
  conffile.close()
else:
  print "Err: No config file found"
  sys.exit(2)

#parse counters and their thresholds:

error_counters={}
for item in conf['thresholds']:
  counter_name=str(item['counter'])
  error_counters[counter_name]={}
  error_counters[counter_name]['crit']=item['crit']
  error_counters[counter_name]['warn']=item['warn']

if debug:
  print str(error_counters)



command_string='opaextractlids -q -F nodetype:FI'
runtime_info_message("extracting LIDs from fabric.. (" + str(command_string) + ")",start_time)
cmd = Command(command_string)
(rc_oel,stdout_oel,stderr_oel) = cmd.run(15)	#15 sec is enough for everyone. :)

command_string='opaextracterror -q'
runtime_info_message("extracting error counters from fabric.. (" + str(command_string) + ")",start_time)
cmd = Command(command_string)
(rc_oee,stdout_oee,stderr_oee) = cmd.run(30)        #30 sec is enough for everyone. :)

command_string='opareport -q -o links'
runtime_info_message("extracting link info from fabric.. (" + str(command_string) + ")", start_time)
cmd = Command(command_string)
(rc_orl,stdout_orl,stderr_orl) = cmd.run(30)        #30 sec is enough for everyone. :)

command_string='opareport -o nodes -d 1'
runtime_info_message("extracting node info from fabric.. (" + str(command_string) + ")", start_time)
cmd = Command(command_string)
(rc_orn,stdout_orn,stderr_orn) = cmd.run(30)        #30 sec is enough for everyone. :)


runtime_info_message("Data analysis and transformations:", start_time )

# first data structure: fabric[]
# - dictionary where guid is key

runtime_info_message("creating fabric and node2guid structures", start_time )

fabric={}
node2guid={}

#..parse the opaextractLID:

try:
  opa_extract_lids_csv_reader = csv.reader(stdout_oel.splitlines(), delimiter=';')
except:
  print "ERR: csv parse orror in opaextractlids output."
  sys.exit(int(Icinga.STATE_UNKNOWN))

csv_headers = ['SystemImageGUID','PortNum','NodeType','NodeDesc','LID']	#there is no CSV header so we'll create it manually..
opa_extract_lids_csv_columns_count=int(len(csv_headers))

for row in opa_extract_lids_csv_reader:        #now iterate over lines and create dictionary from every line
  guid=row[0]
  if not guid in fabric: fabric[guid]={}	#create key

  oel={}
  for column_number in range(0,opa_extract_lids_csv_columns_count):
    key=csv_headers[column_number]
    value=row[column_number]
    oel[key]=value
  fabric[guid]['opa_extract_lids']=oel

  #and create the node -> guid mapping (yes, for switches it will make no sense..(?)
  node2guid[parse_node_from_nodedesc(row[3])]=guid


runtime_info_message("Parsing opa_error data structure",start_time)

#..and parse the lines from Opa Extract Error csv output

try: 
  opa_extract_error_csv_reader = csv.reader(stdout_oee.splitlines(), delimiter=';')
except: 
  print "ERR: csv parse orror in opaextracterror output."
  sys.exit(int(Icinga.STATE_UNKNOWN))

opa_errors={}

#this is in the CSV variable now:
#['NodeDesc', 'SystemImageGUID', 'PortNum', 'LinkSpeedActive', 'LinkWidthDnGradeTxActive', 'LinkWidthDnGradeRxActive', 'LinkQualityIndicator', 'RcvSwitchRelayErrors', 'LocalLinkIntegrityErrors', 'RcvErrors', 'ExcessiveBufferOverruns', 'FMConfigErrors', 'LinkErrorRecovery', 'LinkDowned', 'UncorrectableErrors', 'RcvConstraintErrors', 'XmitConstraintErrors']
#['co1195 hfi1_0', '0x001175010108866d', '1', '25Gb', '4', '4', '5', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0']

#parse headers now:

csv_headers = opa_extract_error_csv_reader.next()	#headers are the first line in CSV
opa_extract_error_csv_columns_count=int(len(csv_headers))

for row in opa_extract_error_csv_reader:	#now iterate over lines and create dictionary from every line
  guid=row[1]
  portnr=row[2]
  node_desc=row[0]
  oee={}
  
  if not guid in fabric: fabric[guid]={}	#create key it it's not there..
  if not str(parse_node_from_nodedesc(row[0])) in node2guid: node2guid[str(parse_node_from_nodedesc(row[0]))]=guid	#create key if it's not there..

  for column_number in range(0,opa_extract_error_csv_columns_count):
    oee[csv_headers[column_number]]=row[column_number]

  fabric[guid]['opa_extract_error']=oee

  if not node_desc in opa_errors: opa_errors[node_desc]={}
  if not portnr in opa_errors[node_desc]: opa_errors[node_desc][int(portnr)]=oee

runtime_info_message("Extracting top level switches",start_time)

#and parse the top-level-fabric switches, their nodeguid and image guid
# we look for following pattern:
#
#     Name: top01
#         NodeGUID: 0x00117501020c4752 Type: SW
#         Ports: 48 PartitionCap: 32 SystemImageGuid: 0x00117501ff0c4752
#

#here: conf['top_level_switch_name_pattern'] is string "top" - as a top level switch pattern:

name_line_pattern = re.compile("\s+Name:\s+top\w+")
node_guid_pattern = re.compile("\s+NodeGUID:\s+\w{16}")
system_image_guid_pattern = re.compile("SystemImageGuid:")

top_level_switch_name=None
top_level_switch_node_guid=None
top_level_switch_image_guid=None

top_level_switches={}

for line in stdout_orn.splitlines():
  if not top_level_switch_name and not top_level_switch_node_guid and not top_level_switch_image_guid:
    #we're looking for first line:
    if name_line_pattern.search(str(line)):
      #name matched
      top_level_switch_name = str(line.split()[1]).strip()
      continue
  elif top_level_switch_name and not top_level_switch_node_guid and not top_level_switch_image_guid:
    #we have switch name, we're looking for second line - the one with NodeGUID:
    if node_guid_pattern.search(str(line)):
      #matched, good
      top_level_switch_node_guid = str(str(line).strip().split(' ')[1])
      continue
    else:
      top_level_switch_name = None  #some mistake, broken format etc.
      continue
  elif top_level_switch_name and top_level_switch_node_guid and not top_level_switch_image_guid:
    #we have switch name, we have node guid, we're looking for image guid:
    if system_image_guid_pattern.search(str(line)):
      #matched, good
      top_level_switch_image_guid = str(line.split()[5]).strip()
      #now we have everyhing
      top_level_switches[top_level_switch_name] = (top_level_switch_node_guid,top_level_switch_image_guid)
      #reset the loop variables:
      top_level_switch_node_guid = None
      top_level_switch_image_guid =None
      top_level_switch_name = None
      continue
    else:
      top_level_switch_name = None  #some mistake, broken format, etc. lets reset and start from the 0
      top_level_switch_node_guid = None
      continue

runtime_info_message("NodeGUID <-> SystemImageGuid lookup table parsing..",start_time)

#and parse the NodeGuid to SystemImageGuid
# we look for following patterns:
# NodeGUID: 0x00117501027bc7c6 Type: SW
# Ports: 48 PartitionCap: 32 SystemImageGuid: 0x00117501fb000485

node_guid_pattern = re.compile("\s+NodeGUID:\s\w{16}")
system_image_guid_pattern = re.compile("SystemImageGuid:")

node_guid_matched = False

node_guid_to_system_image_guid={}
system_image_guid_to_node_guid={}

for line in stdout_orn.splitlines():
  if not node_guid_matched:
    if node_guid_pattern.search(str(line)) and "SW" in str(line):
      line_splitted = line.split()
      node_guid_matched = True
      node_guid=line_splitted[1]
  else:
    if system_image_guid_pattern.search(str(line)):
      line_splitted = line.split()
      system_image_guid=line_splitted[5]
      node_guid_to_system_image_guid[node_guid]=system_image_guid
      node_guid_matched = False
    else:
      node_guid_matched = False

#parse the links between switches

#100g 0x00117501020c3864  25 SW   top06
#<->  0x001175010277954a   8 SW   opa4 L121B

runtime_info_message("Parsing interswitch links",start_time)

first_line_pattern = re.compile("^\d+g\s+0x\w{16}\s+\d+\s+SW")
second_line_pattern = re.compile("^<->\s+0x\w{16}\s+\d+\s+SW")

src_nodedesc=None
src_portnr=None

dest_nodedesc=None
dest_portnr=None

inter_switch_links = {}

for row in stdout_orl.splitlines():
  if not src_nodedesc and not src_portnr and not dest_nodedesc and not dest_portnr:
    if first_line_pattern.search(str(row)):
      row_splitted=row.split()
      src_portnr = str(row_splitted[2]).strip()
      src_nodedesc = ""
      for row_splitted_index in range(4,len(row_splitted)):
        src_nodedesc = src_nodedesc + row_splitted[row_splitted_index] + " "
      src_nodedesc=src_nodedesc.strip()
      continue

  if src_nodedesc and src_portnr and not dest_nodedesc and not dest_portnr:
    if second_line_pattern.search(str(row)):
      row_splitted = row.split()
      dest_portnr = str(row_splitted[2]).strip()
      dest_nodedesc = ""
      for row_splitted_index in range(4,len(row_splitted)):
        dest_nodedesc = dest_nodedesc + row_splitted[row_splitted_index] + " "
      dest_nodedesc=dest_nodedesc.strip()
      #now we have what we want
      if not src_nodedesc in inter_switch_links: inter_switch_links[src_nodedesc]={}
      if not dest_nodedesc in inter_switch_links: inter_switch_links[dest_nodedesc]={}
      inter_switch_links[src_nodedesc][src_portnr]=(dest_nodedesc,dest_portnr)  #save the result into structure
      inter_switch_links[dest_nodedesc][dest_portnr]=(src_nodedesc,src_portnr)  #and the reverse path too.

      #reset the state
      src_nodedesc = None
      src_portnr = None
      dest_nodedesc = None
      dest_portnr = None
      continue

    else:
      #reset the state too as most likely broken input or smth like this..
      src_nodedesc = None
      src_portnr = None
      dest_nodedesc = None
      dest_portnr = None
      continue


runtime_info_message("Parsing node neighboors",start_time)

#and parse the opareport links now - stdout_orl should look like:

#Link Summary

#5967 Links in Fabric:
#Rate NodeGUID          Port Type Name
#100g 0x001175010108866d   1 FI   co1195 hfi1_0
#<->  0x00117501027ab700   3 SW   opa1 L113B
#...
#100g 0x001175010277aef2  39 SW   opa2 S201B
#<->  0x0011750102783f83  39 SW   opa2 L121A
#-------------------------------------------------------------------------------


node_pattern = re.compile("^\d+g\s+0x\w{16}\s+\d+\s+FI") #search for 100g 0x001175010108866d   1 FI   co1195 hfi1_0
ds_pattern = re.compile("^<->\s+0x\w{16}\s+\d+\s+SW") #same as above but different. :)

node_found=False

#reset variables:

node_guid = None
node_nodedesc = None

for row in stdout_orl.splitlines():

  if node_found:	#we expect line describing the director switch line:
    if ds_pattern.search(str(row)):
      row_splitted=row.split()	#smth like: ['<->', '0x00117501027aaa65', '9', 'SW', 'opa3', 'L112B']

      switch_guid=row_splitted[1]
      switch_port=row_splitted[2]

      #the rest of line will be nodedesc
      switch_nodedesc=""
      for row_splitted_index in range(4,len(row_splitted)):
        switch_nodedesc=switch_nodedesc+row_splitted[row_splitted_index] + " "

      #print "link info: node_guid: " + str(node_guid) + " (" + str(node_nodedesc) + ") switch guid: " + str(switch_guid) + ", port: " + str(switch_port) + ", desc: " + str(switch_nodedesc)
      if node_guid in fabric:
        fabric[node_guid]['nb'] = ( switch_guid,switch_port,switch_nodedesc)  #the switch guid is NODEGUID - not PORT_GUID (!) :(
      else:
        print "err: node is missing in fabric, strange error."

      node_found=False
    else:
      node_found=False
  else:
    if node_pattern.search(str(row)):
      row_splitted=row.split()  #smth like: ['100g', '0x001175010108866d', '1', 'FI', 'co1195', 'hfi1_0']
      node_guid=row_splitted[1]

      node_nodedesc=""
      for row_splitted_index in range(4,len(row_splitted)):
        node_nodedesc = node_nodedesc + row_splitted[row_splitted_index] + " "
      node_found=True
    else:
      node_guid=None
      node_found=False


runtime_info_message("Processing nodes",start_time)

#iterate over nodes and checks good and bad things:
session = prepare_session('externalchecks','externalchecks')


#stats structure
stats=Stats()

for node in node2guid:  #provide results for nodes

  #reset the loop variables where needed:
  os=""

  try:
    # parse data from fabric data structures:

    nb=fabric[node2guid[node]]['nb']                  #get neighboor node guid
    nb_image = node_guid_to_system_image_guid[nb[0]]  #convert to image guid

    remote_errors = opa_errors[str(nb[2]).strip()][int(nb[1])]    #get error data structure for remote port
    local_errors = fabric[node2guid[node]]['opa_extract_error']   #get error data structure for local port

    local_lid=fabric[node2guid[node]]['opa_extract_lids']['LID']

    remote_port_guid=nb[0]
    remote_port_portnr=nb[1]
    remote_port_nodedesc=nb[2]

  except KeyError:
#    raise  #for debug uncomment
    continue    #there are some data missing, let's take different node

  crit=False
  warn=False

  (r_crit,r_warn,r_os) = check_port(remote_errors)
  (l_crit,l_warn,l_os) = check_port(local_errors)

  #process return code:
  if r_crit or l_crit:
    crit=True
  elif r_warn or l_warn:
    warn=True

  #header for the output

  if l_crit or l_warn:
    os=str(os)+"local port problem"
  if r_crit or r_warn:
    os=str(os)+"remote port problem"

  if not (l_crit or l_warn) and not (r_crit or r_warn):
    os=str(os)+"[OK] - both sides of link are OK"

  os=str(os)+'\n'

  os=str(os)+"<p>"
  os=str(os)+"<b>Local port summary</b>"
  os=str(os)+str(l_os)
  os=str(os)+'</p>'

  os=str(os)+"<p>"
  os=str(os)+"<b>Remote port summary</b>"
  os=str(os)+str(r_os)
  os=str(os)+"</p>"

  #print "OS" + str(os)

  oc=0
  node_fqdn=str(node) + str(conf['node_to_fqdn_suffix'])

  if warn: oc=1
  if crit: oc=2

  session = prepare_session(conf['api_user'],conf['api_pass'])	#for every POST we need new session. thats "feature" of ICINGA. lel. :( :)
  result = post_check_result(conf['api_host'],int(conf['api_port']),str(node_fqdn),"external-poc-OPA-quality",int(oc),str(os),conf['check_source'])

#check the TOP switches if they have expected amount of downlinks:

runtime_info_message("Processing top level switches",start_time)

for switch in top_level_switches:
  oc=0
  os=""

  switch_fqdn=str(switch) + str(conf['node_to_fqdn_suffix'])

  #print "switch: " + str(switch)
  #count the ports:
  portcount=0
  for port in opa_errors[switch]:
    portcount=portcount+1
  #print "port count" + str(portcount)
  if int(conf['top_level_switch_downlinks_count']) != int(portcount):
    os = "[WARNING] different (" + str(portcount) + ") than expected (" + str(conf['top_level_switch_downlinks_count'])+ ") downlinks port count found on this switch."
    oc=1
  else:
    os = "[OK] expected downlinks port count found (" + str(portcount) + ")"
    oc=0

  session = prepare_session(conf['api_user'],conf['api_pass'])	#for every POST we need new session. thats "feature" of ICINGA. lel. :( :)
  result = post_check_result(conf['api_host'],int(conf['api_port']),str(switch_fqdn),"external-poc-downlink-port-count",int(oc),str(os),conf['check_source'])

  #now check and post the downlink health:

  os_links = "header\n"
  oc_links = 0
  warn=False
  crit=False

  for port in inter_switch_links[switch]:
    try:
      local_errors = opa_errors[switch][int(port)]

      remote_switch_nodedesc = inter_switch_links[switch][port][0]
      remote_switch_portnr = inter_switch_links[switch][port][1]
      remote_errors = opa_errors[remote_switch_nodedesc][int(remote_switch_portnr)]

      (r_crit, r_warn, r_os) = check_port(remote_errors, hide_good=True) #we don't want to see good ports, bcs. there is too much of them
      (l_crit, l_warn, l_os) = check_port(local_errors, hide_good=True)

      if r_crit or l_crit: crit = True
      if r_warn or l_warn: warn = True

      if l_crit or l_warn:
        os_links = str(os_links) + "<p><b> local port " + str(port) + " is not healthy: </b></p>"
        os_links = str(os_links) + str(l_os)

      if r_crit or r_warn:
        os_links = str(os_links) + "<p><b> remote port connected to port " + str(port) + " is not healthy: </b></p>"
        os_links = str(os_links) + str(r_os)

    except KeyError:
      print "err: key missing"
      raise
      pass

  if crit or crit: oc_links = 2
  elif warn or warn: oc_links = 1

  session = prepare_session(conf['api_user'],conf['api_pass'])	#for every POST we need new session. thats "feature" of ICINGA. lel. :( :)
  result = post_check_result(conf['api_host'],int(conf['api_port']),str(switch_fqdn),"external-poc-downlink-port-health",int(oc_links),str(os_links),conf['check_source'])

runtime_info_message("Processing spine-card-switches",start_time)

spines=conf['spines']

for spine in spines:
  spine_hostname = str(spine).replace(' ','_') #in icinga there are no spaces alowed there in object naming
  check_switch_ports(spine,spine_hostname)

runtime_info_message("spine switches done",start_time)

others=conf['others']

for switch in others:
  switch_hostname = str(switch).replace(' ','_') #in icinga there are no spaces alowed there in object naming
  check_switch_ports(switch,switch_hostname)

runtime_info_message("other switches done",start_time)