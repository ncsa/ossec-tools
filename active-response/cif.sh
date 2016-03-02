#!/bin/bash
# Generates intel feed entries for CIF
# Author: Jon Schipp
CHAT=/usr/local/bin/ircsay
CHANNEL="#feeds"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
DESCRIPTION=$(grep -h -A 10 '<rule id="'"$RULEID"'"' /var/ossec/rules/*.xml | awk -F '[<>]' '/description/ { printf("%s", $3) } END { printf("\n") }')
FILE=/var/www/html/ossec.csv

# Logging the call
echo "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8" >> ${PWD}/../logs/active-responses.log

[[ $IP ]] || exit

# RFC 1918
[[ $IP =~ ^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && exit
[[ $IP =~ ^172\.16\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && exit
[[ $IP =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && exit
# Add other networks to skip

printf "${IP},OSSEC,${RULEID},${DESCRIPTION}\n" >> $FILE
[[ -f $CHAT ]] && printf "${IP},OSSEC,${RULEID},${DESCRIPTION}\n" | $CHAT "$CHANNEL" -
