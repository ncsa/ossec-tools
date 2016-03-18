# ossec-tools
Scripts and integrations for OSSEC. With the following code and configurations
we transformed our OSSEC deployment from an overwhelming mess of alerts to a
manageable and useful system where most of the alerts we actually care about.

It includes things like code to block hosts at our perimeter, create intelligence feeds from
the logs, and only e-mail alerts when a file has changed that is not managed by Puppet and is different from
what's reported by the package manager's checksums - meaning no alerts for files changed after package updates :)

## Active Response
Custom AR scripts

* active-response/virustotal_lookup.sh/virus_total.py - Look up hash from syscheck alerts in VT database
* active-response/cymru_lookup.sh - Look up hash from sysheck alerts in Team Cymru Malware Hash Registery
* active-response/puppetdb_lookup.sh - Look up managed files in PuppetDB
* active-response/rpm_lookup.sh - Look up files that changed from RPM install (must be present on agents)
* active-response/deb_lookup.sh - Lookup file that changes from DEB install (must be present on agents)
* active-response/time_lookup.sh - Check if system clock is off or time zone differs for analyzed logs
* active-response/ldap_lookup.sh - Lookup employee usernames in LDAP database
* active-response/command_search.sh - Search for malicious commands across logs
* active-response/cif.sh - Create intelligence feed from alerts
* active-response/bhr.sh - Block hosts at perimeter using Black Hole Router by Justin Azoff
* active-response/add_to_cdb.sh - Add entries from alerts to system database e.g. system users
* active-response/rule-all.sh - Run many of the above scripts
* active-response/syscheck-all.sh - Run many of the syscheck scripts

Many of the scripts generate logs which are fed into OSSEC, decoded, and analyzed. 
The decoders and rules are in the respective sections below. Don't include anything you don't need.
For example, if you don't use puppet for configuration management or run Debian system don't include
the puppetdb_lookup or rpm_lookup configurations.

1. Server: copy all the files above to `$OSSEC/active-response/bin/` directory.
2. Server: edit `$OSSEC/etc/ossec.conf` with the AR and localfile configuration.
```
  <command>
    <name>syscheck_all</name>
    <executable>syscheck-all.sh</executable>
    <expect>filename</expect>
  </command>

  <command>
    <name>ip_all</name>
    <executable>rule-all.sh</executable>
    <expect>srcip</expect>
  </command>

  <command>
    <name>rule_all</name>
    <executable>rule-all.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>rpm_lookup</name>
    <executable>rpm_lookup.sh</executable>
    <expect>filename</expect>
  </command>

  <command>
    <name>deb_lookup</name>
    <executable>deb_lookup.sh</executable>
    <expect>filename</expect>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

 <active-response>
    <command>syscheck_all</command>
    <rules_group>syscheck,,</rules_group>
    <level>5</level>
    <location>server</location>
  </active-response>

  <active-response>
    <command>rpm_lookup</command>
    <rules_group>syscheck,,</rules_group>
    <level>5</level>
    <location>local</location>
  </active-response>

  <active-response>
    <command>deb_lookup</command>
    <rules_group>syscheck,,</rules_group>
    <level>5</level>
    <location>local</location>
  </active-response>

  <active-response>
    <command>ip_all</command>
    <level>4</level>
    <location>server</location>
  </active-response>

  <active-response>
    <command>rule_all</command>
    <level>4</level>
    <location>server</location>
  </active-response>

  <active-response>
    <command>restart-ossec</command>
    <location>local</location>
    <rules_id>110003</rules_id>
  </active-response>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/puppetdb_lookup.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/virustotal_lookup.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/cymru_lookup.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/rpm_lookup.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/deb_lookup.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/command_search.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/time_lookup.log</location>
  </localfile>
```
3. Agent: copy `rpm_lookup.sh` and `deb_lookup.sh` to `$OSSEC/active-response/bin/` and localfile config to `$OSSEC/etc/ossec.conf`.
```
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/rpm_lookup.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/deb_lookup.log</location>
  </localfile>
```

4. Server: Add `organization_ar_rules.xml` to `$OSSEC/rules/` and include the rules in `$OSSEC/etc/ossec.conf`.
5. Server: Add `active_response.xml` decoder to `$OSSEC/etc/` and include the decoder in `$OSSEC/etc/ossec.conf`.
6. Agent/Server: Before restarting create the log files so OSSEC begins reading them e.g. `touch $OSSEC/logs/{deb,rpm}_lookup.sh`
7. Restart the server and agent OSSEC software

## Decoders
Custom decoders

* decoders/kerberos.xml - Decoder for ksu and kadmind logs
* decoders/active_response.xml - Decoder for logs generated from our active response scripts
* decoders/sudo.xml - Improved sudo decoder 

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
[ossec_ar_stats]
user root
[ossec_stats]
user root
[ossec_top_groups]
user root
[ossec_top_rules]
user root
```

![Munin Graphs](https://raw.githubusercontent.com/ncsa/ossec-tools/master/munin/ossec_munin.png)

## Nagios
Plugins to check OSSEC services. There's two scripts but the python script `check_ossec.py` is newer and has more features.
Examples of both are listed below.

* Check status of OSSEC services excluding active response service (execd)
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
