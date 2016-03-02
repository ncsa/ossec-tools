#!/bin/bash
TOKEN="<put BHR token here>"
URL="https://bhr.org.tld/bhr/api/block"
CHAT=/usr/local/bin/ircsay
CHANNEL="#host-blocks"
IP=$3
RULEID=$5
MESSAGE='OSSEC Rule '$RULEID''

TIMEOUT=900

# Requires IP
[[ $IP ]] || exit

# Don't block your nets
[[ $IP =~ ^10\.1\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && exit

# Skip RFC 1918 addresses
[[ $IP =~ ^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && exit
[[ $IP =~ ^172\.16\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && exit
[[ $IP =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && exit

# Only block for these rules
[[ $RULEID =~ ^(5703|5712|31153|100022)$ ]] || exit

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> ${PWD}/../logs/active-responses.log

curl -X POST -H "Authorization: Token ${TOKEN}" $URL \
        --data-urlencode source="ossec" \
        --data-urlencode duration="${TIMEOUT}" \
        --data-urlencode why="${MESSAGE}" \
        --data-urlencode cidr="${IP}/32" \
        --data-urlencode autoscale="1"

[[ -f $CHAT ]] && printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" | $CHAT "$CHANNEL" -
