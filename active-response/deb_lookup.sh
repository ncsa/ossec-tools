#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/deb_lookup.log"
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

get_hash(){
  # Obtain hash from lines e.g. "2eb1a3e346933962bdfbb7b118404b68  /bin/ls"
  local line="$@"
  printf "${line% *}\n"
}

deb_lookup() {
  local file="$1"
  results="$(dpkg -S "$file" 2>/dev/null)"
  [[ "$results" ]] || die "WARNING: $file not installed by package"
  pkg="${results%%:*}"
  hashfile="/var/lib/dpkg/info/$pkg.md5sums"
  [[ -s "$hashfile" ]] || die "ERROR: db $hashfile not available or empty"
  match="$(grep -w "${file#/}" "$hashfile")"
  db_hash=$(get_hash "$match")
  line="$(md5sum "$file")"
  fs_hash="$(get_hash "$line")"
  [[ "$db_hash" = "$fs_hash" ]] || return 1
  return 0
}

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> $AR_LOG
# System must be Debian based
[[ -f /etc/debian_version ]] || exit 0

# We need a filename
[[ "$FILENAME" ]] || die "No file given"

deb_lookup "$FILENAME" || die "WARNING: ${FILENAME:-(empty)} differs from DEB database"
log "OK: ${FILENAME:-(empty)} DEB verification passed"
exit 0
