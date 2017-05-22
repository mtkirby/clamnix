#!/bin/bash
# 20170509 Kirby

if [[ $SPLUNK_HOME =~ forwarder ]]
then
    exit 0
fi

if ! freshclam >/dev/null 2>&1
then
    echo "FAILURE: unable to run freshclam"
    exit 1
fi

dbdir="$SPLUNK_HOME"/etc/deployment-apps/clamnix/unixclamdb
clamdir="/var/lib/clamav"

# the main and daily files will have either a .cvd or .cld extension
for file in "$clamdir"/main.c?d "$clamdir"/daily.c?d
do
    files[${#files[@]}]="$file"
done

if [[ ${#files[@]} == 0 ]]
then
    echo "FAILURE: no main/daily files in $clamdir"
    exit 1
fi

if ! which sigtool >/dev/null 2>&1
then
    echo "FAILURE: sigtool not found"
    exit 1
fi

mkdir "$dbdir" >/dev/null 2>&1
if ! cd "$dbdir"
then
    echo "FAILURE: unable to chdir $dbdir"
    exit 1
fi

for file in "${files[@]}"
do
    if ! sigtool -u "$file" 2>&1
    then
        echo "FAILURE: sigtool failed on $file"
    fi
done

# .mdb is PE section based hash signatures
# It is not needed for unix/linux scans
rm -f "$dbdir"/*.mdb >/dev/null 2>&1

# Filter the Unix. signatures
# Goal is to remove any Win. signatures, so match on that and filter Unix.
for file in daily.h?? *.ndb main.hdb
do
    if grep -q 'Win\.' "$file"
    then
        grep 'Unix\.' "$file" > new
        mv -f new "$file"
    fi
done

if [[ -d "$SPLUNK_HOME"/etc/apps/clamnix ]]
then
    mkdir "$SPLUNK_HOME"/etc/apps/clamnix/unixclamdb >/dev/null 2>&1
    cp -f "$dbdir"/* "$SPLUNK_HOME"/etc/apps/clamnix/unixclamdb/ >/dev/null 2>&1
fi

#ClamAV-VDB:16 Mar 2016 23-17 +0000:57:4218790:60:X:X:amishhammer:1458170226
maindate=$(egrep '^ClamAV-VDB:' main.info |cut -d':' -f2)
dailydate=$(egrep '^ClamAV-VDB:' daily.info |cut -d':' -f2)

echo "maindate=\"$maindate\" dailydate=\"$dailydate\""

