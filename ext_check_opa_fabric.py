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

import xml.etree.ElementTree as ET	#xml

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
    sys.exit(int(STATE_UNKNOWN))

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
  l_os=str(l_os)+str(message)+'\n'

  return (l_crit,l_warn,l_os)

def parse_node_from_nodedesc(node_desc):
  return node_desc.split(' ')[0].strip()


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

  #and create the node -> guid mapping (yes, for switches it will make no sense..
  node2guid[parse_node_from_nodedesc(row[3])]=guid

print "LIDs parsed.."

#..and parse the lines from Opa Extract Error:

try: 
  opa_extract_error_csv_reader = csv.reader(stdout_oee.splitlines(), delimiter=';')
except: 
  print "ERR: csv parse orror in opaextracterror output."
  sys.exit(int(Icinga.STATE_UNKNOWN))

#this is in the CSV variable now:
#['NodeDesc', 'SystemImageGUID', 'PortNum', 'LinkSpeedActive', 'LinkWidthDnGradeTxActive', 'LinkWidthDnGradeRxActive', 'LinkQualityIndicator', 'RcvSwitchRelayErrors', 'LocalLinkIntegrityErrors', 'RcvErrors', 'ExcessiveBufferOverruns', 'FMConfigErrors', 'LinkErrorRecovery', 'LinkDowned', 'UncorrectableErrors', 'RcvConstraintErrors', 'XmitConstraintErrors']
#['co1195 hfi1_0', '0x001175010108866d', '1', '25Gb', '4', '4', '5', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0']

#parse headers now:

csv_headers = opa_extract_error_csv_reader.next()	#headers are the first line in CSV
opa_extract_error_csv_columns_count=int(len(csv_headers))

for row in opa_extract_error_csv_reader:	#now iterate over lines and create dictionary from every line
  guid=row[1]
  oee={}
  
  if not guid in fabric: fabric[guid]={}	#create key it it's not there..
  if not str(parse_node_from_nodedesc(row[0])) in node2guid: node2guid[str(parse_node_from_nodedesc(row[0]))]=guid	#create key if it's not there..

  for column_number in range(0,opa_extract_error_csv_columns_count):
    oee[csv_headers[column_number]]=row[column_number]

  fabric[guid]['opa_extract_error']=oee

print "Errors parsed.."

#and parse the opareport links now:
session = prepare_session('externalchecks','externalchecks')

#stats structure
stats=Stats()
  
for node in node2guid:

  os=""
  os=os+"<b>Comprehensive OPA check:</b>\n"
  try:
    os=os+"LID: " + str(fabric[node2guid[node]]['opa_extract_lids']['LID']) + "\n"
  except KeyError:
    pass	#there are some data missing, we don't care
  
  crit=False
  warn=False

  #LinkQualityIndicator
  (rc,message) = check_indicator(fabric[node2guid[node]]['opa_extract_error']['LinkQualityIndicator'],'LinkQualityIndicator',['5'],['4'])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkSpeedActive
  (rc,message) = check_indicator(fabric[node2guid[node]]['opa_extract_error']['LinkSpeedActive'],'LinkSpeedActive',['25Gb'],[])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkWidthDnGradeTxActive
  (rc,message) = check_indicator(fabric[node2guid[node]]['opa_extract_error']['LinkWidthDnGradeTxActive'],'LinkWidthDnGradeTxActive',['4'],[])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #LinkWidthDnGradeRxActive
  (rc,message) = check_indicator(fabric[node2guid[node]]['opa_extract_error']['LinkWidthDnGradeRxActive'],'LinkWidthDnGradeRxActive',['4'],[])
  (crit,warn,os) = process_check_output(crit,warn,os,rc,message)

  #all err counters:
  for counter in error_counters:
    rs="[OK]"
    value=int(fabric[node2guid[node]]['opa_extract_error'][counter])
    stats.save_stat(fabric,node,value,counter)
    if value>error_counters[counter]['warn']:
      warn=True
      rs="[WARN]"
    if value>error_counters[counter]['crit']:
      crit=True
      rs="[CRIT]"
    os=os+str(rs)+":"+str(counter) + " " + str(value) + "\n"
    

  #print output string and push the value into icinga API

  print str(os)
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





