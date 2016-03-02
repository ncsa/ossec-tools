#!/usr/bin/env bash
# Author: Jon Schipp
PUPPETDB_SOCKET=http://puppet-master:8080
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/puppetdb_lookup.log"
AR_LOG="${PWD}/../logs/active-responses.log"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT="$6"
SERVICE=$7
FILENAME=$8

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

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
  [[ $1 ]] || die "ERROR: ${FUNCNAME}: no argument given"
  argc="$1"
  [[ $argc -ge 5 ]] || return 1
}

get_alert(){
  local id
  [[ $1 ]] || return 1
  id="$1"
  awk -v ts=${id}: 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log || return 1
}

get_host(){
  awk -F "[()]" '/syscheck/ { print $2 }' | tail -n 1
}

get_file(){
  awk -F "['']" '/^File|^New file|changed for:/ { print $2 }'
}

get_dns(){
  local host
  local fqdn
  [[ $1 ]] || return 1
  host="$1"
  #Add domains to search below 
  for name in $host ${host}.domain1.com ${host}.domain2.com
  do
    is_fqdn="$(dig $name +short)"
    [[ "$is_fqdn" ]] && fqdn="$name $fqdn"
  done
  if [[ "$fqdn" ]]; then
    printf "${fqdn}\n"
  else
   return 1
  fi
}

query_api_for_file(){
 local file
 local name
 [[ $# -eq 2 ]] || die "ERROR: ${FUNCNAME}: Not enough arguments given"
 file="$1"
 name="$2"
 CURL="curl --connect-timeout 1 -X GET ${PUPPETDB_SOCKET}/v4/resources/File"
 JSON=$($CURL --data-urlencode 'query=["and",["=", "title", '\""$file"\"'],["=", "certname",'\""$name\""']]' 2>/dev/null)
 [[ "$JSON" ]] || die "ERROR: Something went wrong for API query, empty: ${dir}, $name"
 [[ "$JSON" =~ "$file" ]] ||
 return 1
}

query_api_for_dir(){
 local file
 local name
 [[ $# -eq 2 ]] || die "ERROR: ${FUNCNAME}: Not enough arguments given"
 file="$1"
 name="$2"
 dir=$(dirname $file)
 CURL="curl --connect-timeout 1 -X GET ${PUPPETDB_SOCKET}/v4/resources/File"
 JSON=$($CURL --data-urlencode 'query=["and",["=", "title", '\""$dir"\"'],["=", "certname",'\""$name\""']]' 2>/dev/null)
 [[ "$JSON" ]] || die "ERROR: Something went wrong for API query, empty: ${dir}, $name"
 [[ "$JSON" =~ "$dir" ]] &&
 [[ "$JSON" =~ directory ]] &&
 [[ "$JSON" =~ '"recurse" : true' ]] ||
 return 1
}

check_status(){
 local code
 [[ $1 ]] || die "ERROR: ${FUNCNAME}: No argument"
 code="$1"
 [[ $code -eq 0 ]] && log "OK: File $FILE managed by Puppet for $HOST_NAME" && return 0
 return 1
}

lookup_file(){
  local file
  [[ $1 ]] || return 1
  file="$1"
  printf "File: ${file}\nHost: ${HOST_NAME}\n"
  for name in $DNS_NAMES
  do
    query_api_for_file "$file" "$name"; check_status $? && return 0
    query_api_for_dir  "$file" "$name"; check_status $? && return 0
  done
  return 1
}

# Logging the call
[[ -f "$AR_LOG" ]] && printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 ${8}\n" >> $AR_LOG

# Getting full alert if we're passed arguments (by OSSEC), otherwise assume manual use
if check_args $#
then
  ALERT=$(get_alert $ALERTID) || die "ERROR: Retrieving alert failed"
  # Verify we have alert
  [[ "$ALERT" ]] || die "ERROR: Alert not found by timestamp"
fi

# Get information we need if not in environment
if ! [[ "$HOST_NAME" ]]; then
  HOST_NAME=$(printf "${ALERT}\n" | get_host) || die "ERROR: Retrieving hostname failed"
fi

if ! [[ "$FILENAME" ]]; then
  FILENAME=$(printf "${ALERT}\n" | get_file) || die "ERROR: Retreiving file failed for $HOST_NAME"
fi

# Check for valid DNS names so we don't send more requests to puppet then we have to
DNS_NAMES=$(get_dns $HOST_NAME) || die "ERROR: No matching FQDN found for $HOST_NAME"

# Lookup file in PuppetDB
lookup_file $FILENAME || die "WARNING: File ${FILENAME:-($ALERTID)} not found for $HOST_NAME"
