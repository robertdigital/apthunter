#!/usr/bin/env python3

# Use the argparse library to simplify the command-line argument handling
# https://docs.python.org/3/library/argparse.html
# https://pymotw.com/3/argparse/
import argparse

# Use the json library to simplify the handling of JSON
# https://docs.python.org/3/library/json.html
# https://www.w3schools.com/python/python_json.asp
import json

# Use the elasticsearch library to simplify accessing
# https://elasticsearch-py.readthedocs.io/en/6.3.1/
from elasticsearch import Elasticsearch

# This might help to simplify things, but not necessarily
# https://pypi.org/project/elasticsearch-dsl/
import elasticsearch_dsl

# Used to verify address given
# https://docs.python.org/3/library/ipaddress.html
import ipaddress

# This will parse the command-line arguments for our program
# Very simple example of JSON being used:
# python apthunter.py -wa '{"color":"Red"}'
parser = argparse.ArgumentParser(description="A program to hunt for Advanced Persistent Threats (APT).  It provides a command-line wrapper for the Federated Security Module (FSM) to query the indicies which contain sensor data in Elasticsearch.",
	 prog="apthunter", 
	epilog="Copyright 2019 Wade W. Wesolowsky")
parser.add_argument("-s",
	"--server",
	help="IP address of the Elasticsearch server.  The default server is 127.0.0.1.",
	default="127.0.0.1",
	dest="server_IP",
	action="store")
parser.add_argument("-p",
	"--port",
	help="Port the Elasticsearch server is running on.  The default port is 9200.",
	type=int,
	default=9200,
	dest="port",
	action="store")
parser.add_argument("-ht",
	"--honeytrap",
	help="Search the honeytrap* index in Elasticsearch.  This index will contain HoneyTrap status messages and Honeypot connection attempts.  The argument expects the JSON body for the query.",
	type=json.loads,
	dest="honeytrap_JSON",
	action="store")
parser.add_argument("-log",
	"--logstash",
	help="Search the logstash-* index in Elasticsearch.  This index will contain Zeek network traffic monitoring information.  The argument expects the JSON body for the query.",
	type=json.loads,
	dest="logstash_JSON",
	action="store")
parser.add_argument("-pf",
	"--pfsense",
	help="Search the pfsense-* index in Elasticsearch.  This index will contain firewall status messages and Snort alerts.  The argument expects the JSON body for the query.",
	type=json.loads,
	dest="pfsense_JSON",
	action="store")
parser.add_argument("-ss",
	"--sweetsecurity",
	help="Search the sweet_security index in Elasticsearch.  This index will contain detected device information and port scans.  The argument expects the JSON body for the query.",
	type=json.loads,
	dest="sweetsecurity_JSON",
	action="store")
parser.add_argument("-ssa",
	"--sweetsecurityalerts",
	help="Search the sweet_security_alerts index in Elasticsearch.  This index will contain new (unique) Sweet Security log events.  The argument expects the JSON body for the query.",
	type=json.loads,
	dest="sweetsecurityalerts_JSON",
	action="store")
parser.add_argument("-t",
	"--tardis",
	help="Search the tardis index in Elasticsearch.  This index will contain historical hosts, IP addresses, and websites.  The argument expects the JSON body of the query.",
	type=json.loads,
	dest="tardis_JSON",
	action="store")
parser.add_argument("-wa",
	"--wazuhalerts",
	help="Search the wazuh-alerts-3.x-* index in Elasticsearch.  This index will contain log events above the alert thresholds in Wazuh.  The argument expects the JSON body of the query.",
	type=json.loads,
	dest="wazuhalerts_JSON",
	action="store")
parser.add_argument("-wm",
	"--wazuhmonitoring",
	help="Search the wazuh-monitoring-3.x-* index in Elasticsearch.  This index will contain all Wazuh monitoring logs.  The argument expects the JSON body of the query.",
	type=json.loads,
	dest="wazuhmonitoring_JSON",
	action="store")
parser.add_argument("-win",
	"--winlogbeat",
	help="Search the winlogbeat-* index in Elasticsearch.  This index will contain Windows Even logs.  The argument expects the JSON body of the query.",
	type=json.loads,
	dest="winlogbeat_JSON",
	action="store")
# Store_true will set verbose to True if the argument is specified
parser.add_argument("--verbose",
	help="Outputs useful information to find errors.",
	default=False,
	dest="verbose",
	action="store_true")

# This gets the arguments!
args = parser.parse_args()

# Check the IP server address
try:
    ip = ipaddress.ip_address(args.server_IP)
    #correct IP address found!
except ValueError:
    print(f"Address is invalid: {args.server_IP}")
    raise SystemExit

# Check the port given
if (args.port < 1 or args.port > 65535):
    print("Port is invalid: %i" % args.port)
    raise SystemExit

# Open an Elasticsearch connection using the argument
es = Elasticsearch([
    {'host': args.server_IP, 'port': args.port, 'url_prefix': 'es', 'use_ssl': False},
])

# Query es at the specified index using the body JSON query
#res = es.search(index="test-index", body={"query": {"match_all": {}}})

# Are the arguments initialized?
# https://stackoverflow.com/questions/30487767/check-if-argparse-optional-argument-is-set-or-not

# Stores the result(s) of the queries
results = []

if args.honeytrap_JSON is not None:
    try:
        temp = es.search(index="honeytrap", body=args.honeytrap_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("honeytrap query failed")

if args.logstash_JSON is not None:
    try:
        temp = es.search(index="logstash-*", body=args.logstash_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("logstash query failed")

if args.pfsense_JSON is not None:
    try:
        temp = es.search(index="pfsense-*", body=args.pfsense_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("pfsense query failed")

if args.sweetsecurity_JSON is not None:
    try:
        temp = es.search(index="sweet_security", body=args.sweetsecurity_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("sweet_security query failed")

if args.sweetsecurityalerts_JSON is not None:
    try:
        temp = es.search(index="sweet_security_alerts", body=args.sweetsecurityalerts_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("sweet_security_alerts query failed")

if args.tardis_JSON is not None:
    try:
        temp = es.search(index="tardis", body=args.tardis_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("tardis query failed")

if args.wazuhalerts_JSON is not None:
    try:
        temp = es.search(index="wazuh-alerts-3.x-*", body=args.wazuhalerts_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("wazuh-alerts query failed")

if args.wazuhmonitoring_JSON is not None:
    try:
        temp = es.search(index="wazuh-monitoring-3.x-*", body=args.wazuhmonitoring_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("wazuh-monitoring query failed")

if args.winlogbeat_JSON is not None:
    try:
        temp = es.search(index="winlogbeat-*", body=args.winlogbeat_JSON)
        results.append(temp)
    except:
        #error
        args.verbose and print("wazuhlogbeat query failed")


# Output the results, recommendation was to use f-string
# https://saralgyaan.com/posts/f-string-in-python-usage-guide/

# Hit count total (very, very simple metric)
if len(results) > 0:
    hits = 0
    for result in results:
        hits = hits + result.hits.total
    print(f"Total results: {hits}")

#print("Got %d Hits:" % res['hits']['total']['value'])
#for hit in res['hits']['hits']:
#    print("%(timestamp)s %(author)s: %(text)s" % hit["_source"])
