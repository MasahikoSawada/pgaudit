#!/bin/env/sh

CONFIG_FILE_ORIG=conf/audit.conf.org
CONFIG_FILE=conf/audit.conf

export TZ=PST8PDT

# Prepare for timestamp test.
# 
# Because timestamp of executing regression test is always different,
# we need to adjust timestamp rule in configuration file in order to
# do test properly.
# We expect that regression test for timestamp is done first and it doesn't
# takes long time to start regression test. But to do that more accurate we
# wait at most 1 min here.
CURRENT_TIME=$(date +"%H:%M:%S")
MINUTE_AFTER=$(date +"%H:%M" -d "1min")":00"
SLEEP_TIME=$(expr \( `date --date "${MINUTE_AFTER}" +%s` - `date --date "${CURRENT_TIME}" +%s` \))
sleep ${SLEEP_TIME}

BEGIN_TIME=$(date +"%H:%M")":00"
END_TIME=$(date +"%H:%M" -d "1 min")":00"

sed -e "s/##BEGIN##/${BEGIN_TIME}/g" ${CONFIG_FILE_ORIG} > ${CONFIG_FILE}
sed -ie "s/##END##/${END_TIME}/g" ${CONFIG_FILE}
