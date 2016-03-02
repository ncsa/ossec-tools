#!/usr/bin/env bash
# Author: Jon Schipp <jonschipp@gmail.com>
SCRIPT=$0
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6
SERVICE=$7
FILENAME=$8

# This scripts calls others because only one can be executed by OSSEC

# Match syscheck rules
[[ "$*" =~ syscheck ]] || exit
[[ $RULEID =~ ^(51[069]|55[0-5]|580|59[5-8])$ ]] || exit

die(){
  if [ -f ${COWSAY:-none} ]; then
    $COWSAY -d "$*"
  else
    printf "$*\n"
  fi
  exit 0
}

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)
PUPPET="$PWD/bin/puppetdb_lookup.sh"
CHAT="$PWD/bin/syscheck2chat.sh"
CYMRU="$PWD/bin/cymru_lookup.sh"
VT="$PWD/bin/virustotal_lookup.sh"

printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> ${PWD}/../logs/active-responses.log

# Puppet
[[ -x $PUPPET ]] && $PUPPET $1 $2 $3 $4 $5 $6 $7 $8; found="$?"
[[ $found ]] && [[ $found -eq 0 ]] && exit 0 # If we made it here, file is managed by puppet and we no longer care

# Chat
[[ -x $CHAT ]] && $CHAT $1 $2 $3 $4 $5 $6 $7 $8

# Cymru Hash Lookup
[[ -x $CYMRU ]] && $CYMRU $1 $2 $3 $4 $5 $6 $7 $8

# Virus Total Hash Lookup
[[ -x $VT ]] && $VT $1 $2 $3 $4 $5 $6 $7 $8
