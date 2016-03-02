#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/time_lookup.log"
AR_LOG="${PWD}/../logs/active-responses.log"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6
SERVICE=$7
FILENAME=$8
MAX_TIME=300 # 5 min in seconds

die(){
  printf "$PRE $*\n" | tee -a -- "$LOG"
  exit 1
}

log(){
  printf "$PRE $*\n" >> "$LOG"
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
  alert=$(awk -v ts=$alertid 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log)
  [[ "$alert" ]] || return 1
  printf "$alert\n"
}

convert_timestamp(){
  local ts="$@"
  ts=$(date --date="$ts" +%s)
  [[ "$ts" ]] || return 1
  if [[ ${#ts} -eq 10 ]]; then
    printf "$ts\n"
  else
    return 1
  fi
}

get_timestamp(){
  local alert="$@"
  # Attempt to get timestamp by format
  ts=$(printf "$alert\n" | grep -o '^20[1-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}T[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\.[0-9]\{6\}')
  if [[ "$ts" ]]; then
    epoch=$(convert_timestamp "$ts")
    if [[ "$epoch" ]]; then
      printf "$epoch"
      return 0
    fi
  fi

  ts=$(printf "$alert\n" | grep -o '^[A-Z][a-z]\+ [0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}')
  if [[ "$ts" ]]; then
    epoch=$(convert_timestamp "$ts")
    if [[ "$epoch" ]]; then
      printf "$epoch"
      return 0
    fi
  fi
  # Add more patterns to extract your logs timestamp if they differ

  # If we made it here none of the timestamps matched
  return 1
}

get_hostname(){
  local alert="$@"
  local host
  host=$(printf "$alert\n" | awk '/^2016 [A-Z][a-z][a-z] [0-9][0-9]/ { print $5 }')
  printf "$host\n"
}

check_existing_entry(){
  local host="$1"
  fgrep -q "$host" $LOG || return 1
}

check_timestamp(){
  local ts="$1"
  local host="$2"
  local current=$(date +"%s")
  seconds="$((ts-current))"
  [[ $seconds -lt 0 ]]   && die "WARNING: system clock is ahead by $seconds seconds for $host on $ALERTID"
  [[ $seconds -lt $MAX_TIME ]] || die "WARNING: system clock is behind by $seconds seconds for $host on $ALERTID"
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
ALERT=$(get_alert "$ALERTID") || exit
# Skip if alert has multiple logs
[[ "$ALERT" =~ [Mm]ultiple ]] && exit
# Get timestamp
TS=$(get_timestamp "$ALERT") || die "ERROR: get_timestamp: No timestamp found for $ALERTID"
HOST=$(get_hostname "$ALERT")
# Don't run on ossec logs
[[ $HOST =~ ossec ]] && exit

# Skip writing warning logs if there's an entry for this host already
# This will cut down on alerts
check_existing_entry "$HOST" || exit 1

check_timestamp "$TS" "$HOST"
