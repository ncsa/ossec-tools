#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/command_search.log"
AR_LOG="${PWD}/../logs/active-responses.log"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6
SERVICE=$7
FILENAME=$8

die(){
  echo "$PRE $*" | tee -a -- "$LOG"
  exit 1
}

log(){
  echo "$PRE $*" >> "$LOG"
  exit 0
}

check_args(){
  local argc
  argc="$1"
  [[ $argc -ge 5 ]] || die "ERROR: Not enough arguments given"
}

get_alert(){
  local alert
  local alertid="$1"
  alert=$(awk -v ts=${alertid}: 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log)
  [[ "$alert" ]] || return 1
  echo "$alert"
}

get_msg(){
  local alert="$@"
  msg=$(echo "$alert" | grep '^[A-Z][a-z]\+ [0-9]\+ ')
  echo "$msg"
}

is_skip(){
  local msg="$@"
  # If we find pattern return 1 to skip logging
  echo "$msg" | egrep -q '\]: Updated: Bad protocol version identification|Bad protocol version identification| [iI]nvalid user |mess id 0x' && return 1
  return 0
}

search_commands(){
  local alert="$@"
  local p='[^a-zA-Z0-9\.=]'
  local na='[^a-zA-Z]' # No alpha
  local nan='[^a-zA-Z0-9]' # No alpha & numeric
  local recon="${p}id${p}|uname -a |uname${na}|${p}last${na}|${p}w${nan}|whoami|${p}who${na}|wtmp|btmp|shadow"
  local shells="${p}sh -i|bash -i |${p}bash |${p}sh -c |${p}sh "
  local escalation="${p}wget|${p}ftp |${p}curl|${p}fetch |${p}john${na}|${p}hashcat|crack|sniff|tcpdump|shark "
  local exploitation="msfpayload|msfcli|metasploit|meterpreter"
  local hiding="shred|HIST|history -"
  local commands="${recon}|${shells}|${escalation}|${hiding}"
  msg=$(get_msg "$alert")
  echo "$msg" | egrep -q -- "$commands" || return 1
  is_skip "$msg" || return 1 # Skip logs that we cannot match easily with patterns
  match="$(echo "$msg" | egrep -o -- "$commands")"
  echo "Matched $match in $msg"
}

# Check for arguments
check_args $#

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
[[ -f "$AR_LOG" ]] && echo "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8" >> $AR_LOG

# Getting full alert
ALERT=$(get_alert "$ALERTID") || exit
# Skip alerts with multiple log lines
[[ "$ALERT" =~ [Mm]ultiple ]] && exit
# Get log messages if found command
MSG=$(search_commands "$ALERT") || exit

# Log
log "WARNING: $MSG"
