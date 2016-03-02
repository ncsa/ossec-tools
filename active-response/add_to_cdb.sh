#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/add_to_cdb.log"
AR_LOG="${PWD}/../logs/active-responses.log"
CDB="/var/ossec/lists/system_users.list"
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

is_system_uid(){
  local uid="$1"
  [[ "$uid" ]] || die "ERROR: ${uid:-uid} was not found"
  [[ $uid -le 500 && $uid -gt 0 ]] || return 1
  return 0
}

get_uid_from_alert(){
  local alert="$@"
  local uid_field
  local uid
  uid_field=$(printf "$alert\n" | grep -o 'UID=[0-9]\+')
  uid=${uid_field#*=}
  printf "$uid\n"
}

get_username_from_alert(){
  local alert="$@"
  local name_field
  local username
  name_field=$(printf "$alert\n" | grep -o 'name=[a-zA-Z0-9_]\+')
  name=${name_field#*=}
  printf "$name\n"
}

send_cdb(){
  local username="$1"
  if [[ -w "$CDB" ]]; then
    printf "${username}:system\n" >> $CDB
  fi
}

check_cdb(){
  local username="$1"
  if [[ -r "$CDB" ]]; then
    grep -q "${username}:system" $CDB || return 1
  fi
  exit 0
}

# Check for arguments
check_args $#

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
[[ -f "$AR_LOG" ]] && printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> $AR_LOG

# Only work on rule 5902 'new user'
[[ $RULEID -eq 5902 ]] || die "ERROR: ${RULEID:-ruleid} did not match"

# Getting full alert
ALERT=$(get_alert) || die "ERROR: get_alert: No alert found matching timestamp $ALERTID"

# Extract info from alert
USERID="$(get_uid_from_alert "$ALERT")"
is_system_uid "$USERID" || die "ERROR: UID $USERID is not in the system range"
USER="$(get_username_from_alert "$ALERT")"

# Check if we've looked up this user previously
check_cdb "$USER" || send_cdb "$USER"

# Enable
/var/ossec/bin/ossec-makelists -c /var/ossec/etc/ossec.conf

# Log
log "OK: Added system user $USER to $CDB"
