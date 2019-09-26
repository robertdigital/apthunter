# APT Hunter
<pre><code>
A command-line wrapper to search for APST using our Federated Security Module

usage: apthunter [-h] [-s SERVER_IP] [-p PORT] [-ht HONEYTRAP_JSON]
                 [-log LOGSTASH_JSON] [-pf PFSENSE_JSON]
                 [-ss SWEETSECURITY_JSON] [-ssa SWEETSECURITYALERTS_JSON]
                 [-t TARDIS_JSON] [-wa WAZUHALERTS_JSON]
                 [-wm WAZUHMONITORING_JSON] [-win WINLOGBEAT_JSON] [--verbose]

A program to hunt for Advanced Persistent Threats (APT). It provides a
command-line wrapper for the Federated Security Module (FSM) to query the
indicies which contain sensor data in Elasticsearch.

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_IP, --server SERVER_IP
                        IP address of the Elasticsearch server. The default
                        server is 127.0.0.1.
  -p PORT, --port PORT  Port the Elasticsearch server is running on. The
                        default port is 9200.
  -ht HONEYTRAP_JSON, --honeytrap HONEYTRAP_JSON
                        Search the honeytrap* index in Elasticsearch. This
                        index will contain HoneyTrap status messages and
                        Honeypot connection attempts. The argument expects the
                        JSON body for the query.
  -log LOGSTASH_JSON, --logstash LOGSTASH_JSON
                        Search the logstash-* index in Elasticsearch. This
                        index will contain Zeek network traffic monitoring
                        information. The argument expects the JSON body for
                        the query.
  -pf PFSENSE_JSON, --pfsense PFSENSE_JSON
                        Search the pfsense-* index in Elasticsearch. This
                        index will contain firewall status messages and Snort
                        alerts. The argument expects the JSON body for the
                        query.
  -ss SWEETSECURITY_JSON, --sweetsecurity SWEETSECURITY_JSON
                        Search the sweet_security index in Elasticsearch. This
                        index will contain detected device information and
                        port scans. The argument expects the JSON body for the
                        query.
  -ssa SWEETSECURITYALERTS_JSON, --sweetsecurityalerts SWEETSECURITYALERTS_JSON
                        Search the sweet_security_alerts index in
                        Elasticsearch. This index will contain new (unique)
                        Sweet Security log events. The argument expects the
                        JSON body for the query.
  -t TARDIS_JSON, --tardis TARDIS_JSON
                        Search the tardis index in Elasticsearch. This index
                        will contain historical hosts, IP addresses, and
                        websites. The argument expects the JSON body of the
                        query.
  -wa WAZUHALERTS_JSON, --wazuhalerts WAZUHALERTS_JSON
                        Search the wazuh-alerts-3.x-* index in Elasticsearch.
                        This index will contain log events above the alert
                        thresholds in Wazuh. The argument expects the JSON
                        body of the query.
  -wm WAZUHMONITORING_JSON, --wazuhmonitoring WAZUHMONITORING_JSON
                        Search the wazuh-monitoring-3.x-* index in
                        Elasticsearch. This index will contain all Wazuh
                        monitoring logs. The argument expects the JSON body of
                        the query.
  -win WINLOGBEAT_JSON, --winlogbeat WINLOGBEAT_JSON
                        Search the winlogbeat-* index in Elasticsearch. This
                        index will contain Windows Even logs. The argument
                        expects the JSON body of the query.
  --verbose             Outputs useful information to find errors.

Copyright 2019 Wade W. Wesolowsky
</code></pre>
