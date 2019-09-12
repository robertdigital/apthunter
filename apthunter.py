#Use the argparse library to simplify the command-line argument handling
import argparse

#This will parse the command-line arguments for our program
parser = argparse.ArgumentParser(description="A program to hunt for Advanced Persistent Threats (APT).  It provides a command-line wrapper for the Federated Security Module(FSm) to query the indicies which contain sensor data in Elasticsearch.", prog="apthunter")
parser.add_argument("-s", "--server", help="echo the string you use here", default="127.0.0.1")
parser.add_argument("-p", "--port", help="port of the server", type=int, default=9200)
parser.add_argument("-ht", "--honeytrap", help="Search the honeytrap* index in Elasticsearch.  This index will contain HoneyTrap status messages and Honeypot connection attempts.")
parser.add_argument("-log", "--logstash", help="Search the logstash-* index in Elasticsearch.  This index will contain Zeek network traffic monitoring information.")
parser.add_argument("-pf", "--pfsense", help="Search the pfsense-* index in Elasticsearch.  This index will contain firewall status messages and Snort alerts.")
parser.add_argument("-ss", "--sweetsecurity", help="Search the sweet_security index in Elasticsearch.  This index will contain detected device information and port scans.")
parser.add_argument("-ssa", "--sweetsecurityalerts", help="Search the sweet_security_alerts index in Elasticsearch.  This index will contain new (unique) Sweet Security log events.")
parser.add_argument("-t", "--tardis", help="Search the tardis index in Elasticsearch.  This index will contain historical hosts, IP addresses, and websites.")
parser.add_argument("-wa", "--wazuhalerts", help="Search the wazuh-alerts-3.x-* index in Elasticsearch.  This index will contain log events above the alert thresholds in Wazuh.")
parser.add_argument("-wm", "--wazuhmonitoring", help="Search the wazuh-monitoring-3.x-* index in Elasticsearch.  This index will contain all Wazuh monitoring logs.")
args = parser.parse_args()


