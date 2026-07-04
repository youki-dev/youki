#!/bin/bash

set -x

# change sshd config

file="$1"
param[1]="PermitRootLogin "
param[2]="PubkeyAuthentication"
param[3]="PasswordAuthentication"
if [ -z "${file}" ]
then

file="/etc/ssh/sshd_config"
fi

for PARAM in "${param[@]}"
do
/usr/bin/sed -i '/^'"${PARAM}"'/d' ${file}
/usr/bin/echo "All lines beginning with '${PARAM}' were deleted from ${file}."
done

/usr/bin/echo "${param[1]} yes" >> ${file}
/usr/bin/echo "'${param[1]} yes' was added to ${file}."
/usr/bin/echo "${param[2]} yes" >> ${file}
/usr/bin/echo "'${param[2]} yes' was added to ${file}."
/usr/bin/echo "${param[3]} no" >> ${file}
/usr/bin/echo "'${param[3]} no' was added to ${file}"

# reload config
service sshd reload
