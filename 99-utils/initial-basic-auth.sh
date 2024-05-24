#!/bin/bash

INPUT_FILE=$1
OUTPUT_FILE=$2

rm ${OUTPUT_FILE}
touch ${OUTPUT_FILE}

cat ${INPUT_FILE} | while read line
do
  regex="^(.+?)=(.+)$"
  if [[ $line =~ $regex ]]; then
    USER=$(echo -e "$line" | perl -0777 -ne 'print $1 if /^(.+?)=(.+)$/')
    PASSWD=$(echo -e "$line" | perl -0777 -ne 'print $2 if /^(.+?)=(.+)$/')

    htpasswd -b ${OUTPUT_FILE} ${USER} ${PASSWD}
  fi
done
