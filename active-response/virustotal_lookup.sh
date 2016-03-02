#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/virustotal_lookup.log"
AR_LOG="${PWD}/../logs/active-responses.log"
CDB="/var/ossec/lists/hashes.list"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6
SERVICE=$7
FILENAME=$8

die(){
  [[ -d $(dirname $LOG) ]] && printf "$PRE $*\n" | tee -a $LOG
  exit 1
}

log(){
  [[ -d $(dirname $LOG) ]] && printf "$PRE $*\n" | tee -a $LOG
  exit 0
}

check_args(){
  local argc
  argc="$1"
  [[ $argc -ge 5 ]] || die "ERROR: Not enough arguments given"
}


get_alert(){
  local alert
  alert=$(awk -v ts=$ALERTID 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log)
  [[ "$alert" ]] || return 1
  printf "$alert\n"
}

is_hash(){
  local sha1
  sha1="$1"
  [[ $sha1 ]] || die "ERROR: ${FUNCNAME}: Hash variable empty"
  [[ $sha1 =~ ^\ +$ ]] && die "ERROR: ${FUNCNAME}: Hash variable is only whitespace"
  len="${#sha1}"; [[ $len -eq 40 ]] || die "ERROR: ${FUNCNAME}: The Hash variable does not contain a SHA1 hash"
}

get_hash_from_alert(){
  local alert
  local sha1
  alert="$@"
  [[ "$FILENAME" ]] || FILENAME=$(printf "$alert\n" | awk -F "['']" '/^File|changed for:/ { print $2 }')
  sha1=$(printf "$alert\n" | grep -o '[a-zA-Z0-9]\{40\}' | tail -n 1)
  printf "$sha1\n"
}

get_hash_from_filename(){
  local alert
  local sha1
  alert="$@"
  [[ "$FILENAME" ]] || FILENAME=$(printf "$alert\n" | awk -F "['']" '/^File|changed for:/ { print $2 }')
  [[ -r "$FILENAME" ]]  || die "ERROR: ${FUNCNAME}: File not available on system"
  sha1=$(sha1sum $file | grep -o '[a-zA-Z0-9]\{40\}')
  printf "$sha1\n"
}

virus_lookup(){
   local sha1
   local results
   sha1="$1"
   results=$($PWD/bin/virus_total.py $sha1)
   status_code=$?
   printf "$results\n"
   return $status_code
}

is_executable(){
  local file
  file="$1"
  file -L "$file" 2>/dev/null | egrep -i -q 'script|exec|ELF|object|stripped|linked' || return 1
  return 0
}

send_cdb(){
  local checksum
  local file
  checksum="$1"
  file="$2"
  if [[ -w "$CDB" ]]; then
    printf "${checksum}:${file:-empty}\n" >> $CDB
  fi
}

check_cdb(){
  local checksum
  checksum="$1"
  if [[ -r "$CDB" ]]; then
    grep -q "$checksum" $CDB && exit 0
  fi
}

# Check for arguments
check_args $#

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
[[ -f "$AR_LOG" ]] && printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> $AR_LOG

# Getting full alert
ALERT=$(get_alert) || die "ERROR: get_alert: No alert found matching timestamp $ALERTID"

# Obtain hash
[[ $RULEID -eq 554 ]] && HASH=$(get_hash_from_filename "$ALERT") || HASH=$(get_hash_from_alert "$ALERT")
# Grab host for logging
[[ "$AGENT" ]] || AGENT=$(printf "$ALERT\n" | awk -F "[()]" '/syscheck/ { print $2 }' | tail -n 1)

# Only perform lookups for executable files
is_executable "$FILENAME" || die "OK: ${FILENAME:-(empty)} is not an executable file"

# Verify we do indeed have a hash
is_hash "$HASH"

# Check if we've looked up this hash previously
check_cdb "$HASH"

# Lookup
RESULTS=$(virus_lookup $HASH) || { send_cdb "$HASH" "$FILENAME" && die "OK: No malware found for ${FILENAME:-(empty)} ${HASH:-(empty)} on ${AGENT:-(empty)}"; }

# Log
log "Malicious hash found for ${FILENAME:-(empty)} ($HASH) on ${AGENT:-(empty)}"
