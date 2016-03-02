#!/bin/sh
# Author: Jon Schipp

CHAT=/usr/local/bin/ircsay
CHANNEL="#ossec-syscheck"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

# Check for chat program
[[ -f $CHAT ]] || exit 1

# Match syscheck rules
[[ "$*" =~ syscheck ]] || exit
[[ $RULEID =~ ^(51[069]|55[0-5]|580|59[5-8])$ ]] || exit

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> ${PWD}/../logs/active-responses.log

# Getting full alert
awk -v ts=$ALERTID 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log | $CHAT "$CHANNEL" -
