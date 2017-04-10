#!/bin/bash
# 20170409 Kirby


if [[ $SPLUNK_HOME =~ forwarder ]]
then 
    exit 0
fi


dir="/opt/splunk/etc/deployment-apps/clamnix/unixclamdb"

if [[ ! -f /var/lib/clamav/daily.cld ]] \
|| [[ ! -f /var/lib/clamav/main.cvd ]]
then
    echo "FAILURE: clam files not found in /var/lib/clamav"
    exit 1
fi

if ! which sigtool >/dev/null 2>&1
then
    echo "FAILURE: sigtool not found"
    exit 1
fi

mkdir "$dir" >/dev/null 2>&1
if ! cd "$dir"
then
    echo "FAILURE: unable to chdir $dir"
    exit 1
fi

sigtool -u /var/lib/clamav/daily.cld
sigtool -u /var/lib/clamav/main.cvd

# .mdb is PE section based hash signatures
# It is not needed for unix/linux scans
rm ${dir}/*.mdb

# Filter the Unix. signatures
# Goal is to remove any Win. signatures, so match on that and filter Unix.
for file in daily.h?? *.ndb
do
    if grep -q 'Win\.' "$file"
    then
        grep 'Unix\.' "$file" > new
        mv -f new "$file"
    fi
done

#ClamAV-VDB:16 Mar 2016 23-17 +0000:57:4218790:60:X:X:amishhammer:1458170226
maindate=$(egrep '^ClamAV-VDB:' main.info |cut -d':' -f2)
dailydate=$(egrep '^ClamAV-VDB:' daily.info |cut -d':' -f2)

echo "maindate=\"$maindate\" dailydate=\"$dailydate\""

