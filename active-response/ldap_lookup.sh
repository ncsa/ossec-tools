#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/ldap_lookup.log"
AR_LOG="${PWD}/../logs/active-responses.log"
ALERTS_LOG="${PWD}/../logs/alerts/alerts.log"
CDB="/var/ossec/lists/system_users.list"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6
LDAP_SERVER='ldaps://ldap.company.com/' # Replace
OU='dc=blah,dc=company,dc=com'          # Replace

die(){
  printf "$PRE $*\n" | tee -a $LOG
  exit 1
}

log(){
  printf "$PRE $*\n" | tee -a $LOG
  exit 0
}

check_args(){
  local argc
  argc="$1"
  [[ $argc -ge 5 ]] || die "ERROR: Not enough arguments given"
}

ldap_lookup(){
  local user="$1"
  local server="$2"
  local ou="$3"
  ldap_info=$(ldapsearch -xLLL -b "$ou" -H "$server" "uid=$user" | awk '/uid: / { print $2 }')
  [[ "$ldap_info" ]] || return 1
  return 0
}

get_alert(){
  local alertid="$1"
  local alert
  alert=$(awk -v ts=${alertid}: 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log)
  [[ "$alert" ]] || return 1
  printf "$alert\n"
}

get_user(){
  local alert="$@"
  local user
  [[ "$alert" ]] || return 1
  user=$(echo "$alert"  | awk '/^User: / { print $2 }')
  # Kerberos events and maybe others contain a realm/domain, trim domain
  user=${user%%@*}
  [[ "$user" ]]         || return 1
  [[ "$user" == root ]] && return 1
  printf "$user\n"
}

get_ip(){
  local alert="$@"
  local ip
  [[ "$alert" ]] || return 1
  ip=$(echo "$alert" | awk '/^Src IP: / { print $3 }')
  [[ "$ip" ]] || return 1
  printf "$ip\n"
}

get_hostname(){
  local alert="$@"
  local host
  host=$(printf "$alert\n" | awk '/^20[0-9][0-9] [A-Z][a-z][a-z] [0-9][0-9]/ { print $5 }')
  # above returns strings as host->ip, we just want the IP
  host="${host##*>}"
  printf "$host\n"
}

check_cdb(){
  local username="$1"
  if [[ -r "$CDB" ]]; then
    grep -q "${username}:" $CDB || return 1
  fi
}

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> $AR_LOG

# Check for arguments
check_args $#

# Getting full alert
ALERT=$(get_alert "$ALERTID") || { printf "Log for $ALERTID not found\n" && exit 1; }
# Getting user
USER=$(get_user "$ALERT") || { printf "User not found in $ALERTID\n" && exit 1; }
# Check if system user and exit if true
check_cdb "$USER" && { printf "User $USER found in $CDB\n" && exit 1; }
# Getting source IP
[[ "$IP" == - ]] && IP=$(get_ip "$ALERT")
# Get hostname/ip for logs
[[ "$AGENT" == - ]] && HOST=$(get_hostname "$ALERT") || HOST="$AGENT"

MSG1="Employee lookup for attempted user"
MSG2="Host ${HOST}, Src IP ${IP:-(empty)}, Orig. Alert $ALERTID"
ldap_lookup "$USER" "$LDAP_SERVER" "$OU" || die "WARNING: $MSG1 ${USER}: $MSG2"
log "OK: $MSG1 ${USER}: $MSG2"
exit 0
