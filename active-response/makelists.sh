#!/bin/bash
# Generates CDB lists from intel files
# Author: Jon Schipp

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> ${PWD}/../logs/active-responses.log

# Build CDB databases
/var/ossec/bin/ossec-makelists -c /var/ossec/etc/ossec.conf
