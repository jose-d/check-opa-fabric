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

def post_check_result(icingaserver,icingaserverport,host,check,status,output,source):

  print "posting.."

  URL='https://' + str(icingaserver) + ":" + str(icingaserverport) + '/v1/actions/process-check-result?service=' + str(host) + '!' + str(check)
  try:
    r=session.post(URL,json={'exit_status':str(status),'plugin_output':str(output),'check_source':str(source)},headers={'Accept': 'application/json','Connection':'close'})
    if r.status_code == 200:
      return True
    else:
      return False
  except:
    return False
  
  print "posted."

def uri_validator(x):
  try:
    result = urlparse(x)
    return result.scheme and result.netloc and result.path
  except:
    return False

def check_indicator(value,name,ok_values,warning_values):

  crit=False
  warn=False

  if str(value) in ok_values:
    message="[OK] indicator " + str(name) + " has reference value, " + str(value) + "/" + str(ok_values) + "."
  elif str(value) in warning_values:
    message="[Warning] indicator " + str(name) + " is at warning level, " + str(value) + "/" + str(ok_values) + "."
    warn=True
  else:
    message="[Critical] indicator " + str(name) + " is at critical level, " + str(value) + "/" + str(ok_values) + "."
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

def check_port(port_error_counters):

  crit=False
  warn=False
  os=""

  #LinkQualityIndicator
  (rc,message) = check_indicator(port_error_counters['LinkQualityIndicator'],'LinkQualityIndicator',['5'],['4'])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkSpeedActive
  (rc,message) = check_indicator(port_error_counters['LinkSpeedActive'],'LinkSpeedActive',['25Gb'],[])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkWidthDnGradeTxActive
  (rc,message) = check_indicator(port_error_counters['LinkWidthDnGradeTxActive'],'LinkWidthDnGradeTxActive',['4'],[])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkWidthDnGradeRxActive
  (rc,message) = check_indicator(port_error_counters['LinkWidthDnGradeRxActive'],'LinkWidthDnGradeRxActive',['4'],[])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #all "simple" err counters - we're chacking if number is higher than some threshold.
  for counter in error_counters:
    rs="[OK]"
    value=int(port_error_counters[counter])
    stats.save_stat(fabric,node,value,counter)
    if value>error_counters[counter]['warn']:
      warn=True
      rs="[WARNING]"
    if value>error_counters[counter]['crit']:
      crit=True
      rs="[CRITICAL]"
    os = os + '<p>' + str(rs) + ":" + str(counter) + " " + str(value) + "</p>"

  return (crit,warn,os)



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

# get config from config file - the config file path is now hardcoded..

configpath = os.path.abspath("/usr/local/monitoring/ext_check_opa_fabric.conf")

if os.path.isfile(configpath):
  conffile = open(configpath,'r')
  conf = yaml.safe_load(conffile)
  print "conf"
  print str(conf)
  print "end of conf"
  conffile.close()
else:
  print "No config file found"
  sys.exit(2)

#parse counters and their thresholds:

error_counters={}
for item in conf['thresholds']:
  counter_name=str(item['counter'])
  error_counters[counter_name]={}
  error_counters[counter_name]['crit']=item['crit']
  error_counters[counter_name]['warn']=item['warn']

print str(error_counters)

#execute the opa*tools and parse results:

print "extracting LIDs from fabric.."
command_string='opaextractlids -q -F nodetype:FI'

cmd = Command(command_string)
(rc_oel,stdout_oel,stderr_oel) = cmd.run(15)	#15 sec is enough for everyone. :)

#opaextracterror -q

print "extracting Errors in fabric.."
command_string='opaextracterror -q'

cmd = Command(command_string)
(rc_oee,stdout_oee,stderr_oee) = cmd.run(30)        #30 sec is enough for everyone. :)

#opareport -q -o links

print "extracting Link info from fabric.."
command_string='opareport -q -o links'

cmd = Command(command_string)
(rc_orl,stdout_orl,stderr_orl) = cmd.run(30)        #30 sec is enough for everyone. :)

#opareport -o nodes -N -d 1

print "running opareport -o nodes"
command_string='opareport -o nodes -N -d 1'

cmd = Command(command_string)
(rc_orn,stdout_orn,stderr_orn) = cmd.run(30)        #30 sec is enough for everyone. :)


print "data analysis.."

#fabric data structure - dictionary where hostname is key:

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

print "LIDs parsed.."

#..and parse the lines from Opa Extract Error:

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

print "Errors parsed.."

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
#      print node_guid
  else:
    if system_image_guid_pattern.search(str(line)):
      line_splitted = line.split()
      system_image_guid=line_splitted[5]
#      print system_image_guid
      node_guid_to_system_image_guid[node_guid]=system_image_guid
#      system_image_guid_to_node_guid[system_image_guid]=node_guid  #this make no sense

      node_guid_matched = False
    else:
      node_guid_matched = False


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

      print "link info: node_guid: " + str(node_guid) + " (" + str(node_nodedesc) + ") switch guid: " + str(switch_guid) + ", port: " + str(switch_port) + ", desc: " + str(switch_nodedesc)
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


print "Node neighboors parsed.."

#iterate over nodes and checks good and bad things:
session = prepare_session('externalchecks','externalchecks')


#stats structure
stats=Stats()
  
for node in node2guid:

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
    pass	#there are some data missing, we don't care - most likely this is just disconnected/off node etc.

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

#  os=str(os)+'<p>'

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



  print "OS" + str(os)
  oc=0
  node_fqdn=str(node) + str(conf['node_to_fqdn_suffix'])
  print "fqdn:" + str(node_fqdn)

  if warn: oc=1
  if crit: oc=2

  session = prepare_session(conf['api_user'],conf['api_pass'])	#for every POST we need new session. thats "feature" of ICINGA. lel. :( :)
  result = post_check_result(conf['api_host'],int(conf['api_port']),str(node_fqdn),"external-poc-OPA-quality",int(oc),str(os),conf['check_source'])

print str(stats)

sys.exit(int(Icinga.STATE_UNKNOWN))

#we want to submit smth like this:
#curl -k -s -u seecret:seecret -H 'Accept: application/json' -X POST 'https://localhost:15665/v1/actions/process-check-result?service=icinga_node_hostname!icinga_check_name' -d '{ "exit_status": 0, "plugin_output": "catch me if you can \n aa \n <html><small>a</small></html>",  "check_source": "example.localdomain" }' | python -m json.tool





