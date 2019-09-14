#!/usr/bin/env python3

# Use the argparse library to simplify the command-line argument handling
# https://docs.python.org/3/library/argparse.html
import argparse

# Use the json library to simplify the handling of JSON
# https://docs.python.org/3/library/json.html
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
parser = argparse.ArgumentParser(description="A program to hunt for Advanced Persistent Threats (APT).  It provides a command-line wrapper for the Federated Security Module(FSm) to query the indicies which contain sensor data in Elasticsearch.", prog="apthunter", epilog="Copyright 2019 Wade W. Wesolowsky")
parser.add_argument("-s",
	"--server",
	help="Hostname of the Elasticsearch server.",
	default="127.0.0.1",
	dest="server")
parser.add_argument("-p",
	"--port",
	help="Port the Elasticsearch server is running on.",
	type=int,
	default=9200,
	dest="port")
parser.add_argument("-ht",
	"--honeytrap",
	help="Search the honeytrap* index in Elasticsearch.  This index will contain HoneyTrap status messages and Honeypot connection attempts.",
	type=json.loads,
	dest="honeytrap")
parser.add_argument("-log",
	"--logstash",
	help="Search the logstash-* index in Elasticsearch.  This index will contain Zeek network traffic monitoring information.",
	type=json.loads,
	dest="logstash")
parser.add_argument("-pf",
	"--pfsense",
	help="Search the pfsense-* index in Elasticsearch.  This index will contain firewall status messages and Snort alerts.",
	type=json.loads,
	dest="pfsense")
parser.add_argument("-ss",
	"--sweetsecurity",
	help="Search the sweet_security index in Elasticsearch.  This index will contain detected device information and port scans.",
	type=json.loads,
	dest="sweetsecurity")
parser.add_argument("-ssa",
	"--sweetsecurityalerts",
	help="Search the sweet_security_alerts index in Elasticsearch.  This index will contain new (unique) Sweet Security log events.",
	type=json.loads,
	dest="sweetsecurityalerts")
parser.add_argument("-t",
	"--tardis",
	help="Search the tardis index in Elasticsearch.  This index will contain historical hosts, IP addresses, and websites.",
	type=json.loads,
	dest="tardis")
parser.add_argument("-wa",
	"--wazuhalerts",
	help="Search the wazuh-alerts-3.x-* index in Elasticsearch.  This index will contain log events above the alert thresholds in Wazuh.",
	type=json.loads,
	dest="wazuhalerts")
parser.add_argument("-wm",
	"--wazuhmonitoring",
	help="Search the wazuh-monitoring-3.x-* index in Elasticsearch.  This index will contain all Wazuh monitoring logs.",
	type=json.loads,
	dest="wazuhmonitoring")
parser.add_argument("--debug",
	help="Outputs useful information to find errors.",
	dest="debug")

# This gets the arguments!
args = parser.parse_args()


# Check the IP server address
try:
	ip = ipaddress.ip_address(args.server)
	#correct IP address found!
except ValueError:
	print("Address is invalid: %s" % args.server)
	raise SystemExit

# Check the port given
if (args.port < 1 or args.port > 65535):
	print("Port is invalid: %i" % args.port)
	raise SystemExit

# Open an Elasticsearch connection using the argument
es = Elasticsearch([
    {'host': args.server, 'port': args.port, 'url_prefix': 'es', 'use_ssl': False},
])
