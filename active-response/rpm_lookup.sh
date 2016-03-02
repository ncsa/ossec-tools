#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/rpm_lookup.log"
AR_LOG="${PWD}/../logs/active-responses.log"
ALERTS_LOG="${PWD}/../logs/alerts/alerts.log"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6
[[ "$7" =~ syscheck ]] && FILENAME=$8 || FILENAME=$7

die(){
  printf "$PRE $*\n" | tee -a $LOG
  exit 1
}

log(){
  printf "$PRE $*\n" | tee -a $LOG
  exit 0
}

file_type_lookup(){
  local rpm_info
  rpm_info="$1"
  info=$(printf "$rpm_info" | awk '{ print $2 }')
  TYPE="Regular file"                      # Default to regular file, make changes after
  [[ "$info" == "$FILENAME" ]] && return 0 # True if $2 in rpm_info was empty (no file type info)
  [[ "$info" =~ c ]]           && TYPE="Config file"
  [[ "$info" =~ d ]]           && TYPE="Documentation file"
  [[ "$info" =~ g ]]           && TYPE="GHost file"
  [[ "$info" =~ l ]]           && TYPE="License file"
  [[ "$info" =~ r ]]           && TYPE="Readme file"
}

file_status_lookup(){
  local rpm_flags
  rpm_flags="$1"
  [[ "$rpm_flags" =~ missing ]] && STATUS="File is missing"
  [[ "$STATUS" ]]               || STATUS="Size change"
}

rpm_lookup(){
  local file
  file="$1"
  rpm_info=$(rpm -Vvf "$1" 2>/dev/null | fgrep -w "$1")
  [[ "$rpm_info" ]] || die "No flags output found for $file"
  file_type_lookup "$rpm_info"
  rpm_flags="$(printf "$rpm_info" | cut -d " " -f1)"
  [[ "$rpm_flags" ]] || die "No flags found for $file"
  file_status_lookup "$rpm_flags"
  [[ "$rpm_flags" =~ S|5|missing ]] || return 0
  return 1
}

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> $AR_LOG
# System must be Red Hat based
[[ -f /etc/redhat-release ]] || exit 0

# We need a filename
[[ "$FILENAME" ]] || die "No file given"

rpm_lookup "$FILENAME" || die "WARNING: ${FILENAME:-(empty)} ($TYPE) differs from RPM database ($STATUS)"
log "OK: ${FILENAME:-(empty)} ($TYPE) RPM verification passed"
exit 0
