# ossec-tools
Scripts and integrations for OSSEC

## Active Response
Custom AR scripts

* virustotal_lookup.sh/virus_total.py - Look up hash from syscheck alerts in VT database
* cymru_lookup.sh - Look up hash from sysheck alerts in Team Cymru Malware Hash Registery
* puppetdb_lookup - Look up managed files in PuppetDB
* rpm_lookup - Look up files that changed from RPM install
* deb_lookup - Lookup file that changes from DEB install
* time_lookup - Check if system clock is off for incoming logs
* command_search - Search for malicious commands across logs
* cif.sh - Create intelligence feed from alerts
* bhr.sh - Block hosts at perimeter using Black Hole Router by Justin Azoff
* add_to_cdb.sh - Add entries from alerts to system database e.g. system users
* rule-all.sh - Run many of the above scripts
* syscheck-all.sh - Run many of the syscheck scripts

## Decoders
Custom decoders

* kerberos.xml - Decoder for ksu and kadmind logs
* active_response.xml - Decoder for logs generated from our active response scripts
* sudo.xml - Improved sudo decoder 

## Rules
Custom rules

* rules/kerberos_rules.xml - Kerberos rules
* rules/organization_ar_rules.xml - Active response rules for our AR scripts
* rules/organization_syscheck_rules.xml - Examples of syscheck rules
* rules/organization_rules.xml - Examples of standard log rules
* rules/overwrite_rules.xml - Existing rules that contain modifications

## Munin
Plugins to graph OSSEC stats for Munin

* munin/ossec_ar_stats - Graph active response script usage
* munin/ossec_stats - Graph alert counts by 3 major types of alerts: rules, syscheck, or rootcheck
* munin/ossec_top_groups - Graph alert counts by top 10 rule categories
* munin/ossec_top_rules - Graph alert counts by top 10 rule descriptions

Location
```
$ ls /etc/munin/plugins/ossec_*
/etc/munin/plugins/ossec_ar_stats /etc/munin/plugins/ossec_stats  /etc/munin/plugins/ossec_top_groups /etc/munin/plugins/ossec_top_rules
```

Configuration
```
$ cat /etc/munin/plugin-conf.d/ossec_*
[ossec_stats]
user root
[ossec_top_groups]
user root
[ossec_top_rules]
user root
```

![Munin Graphs](https://raw.githubusercontent.com/ncsa/ossec-tools/master/munin/ossec_munin.png)

## Nagios
Plugins to check OSSEC services

* nagios/check_ossec.py - Checks services, connected agents, syscheck & rootcheck scan times (newer, better than check_ossec.sh)
* nagios/check_ossec.sh - Checks services, connected agents

* Check status of OSSEC services excluding active response i.e. execd
  * `./check_ossec.py -T status`
* Check that all agents are connected except host1
  * `./check_ossec.py -T connected --skip host1.blah.org`
* Check that syscheck has been completed for all agents in the last 12 hours
  * `./check_ossec.py -T syscheck -c 12 -w 6`
* Check that rootkit checks have been completed for all agents in the last 3 hours
  * `./check_ossec.py -T rootcheck -c 12 -w 6`
* Check status of OSSEC services excluding active response i.e. execd
  * `./check_ossec.sh -s execd`
* Check status of OSSEC agent
  * `./check_ossec.sh -a server1`
* Check status of multiple OSSEC agents
  * `./check_ossec.sh -a "server1,server2,station3"`
* Report critical if more than 3 agents are offline and warning if at least 1 is offline.
  * `./check_ossec.sh -c 3 -w 1`
