#!/bin/bash
# 20170412 Kirby
# 20170507 Kirby

export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin:$PATH

if ! which clamscan >/dev/null 2>&1
then
    echo "FAILURE: clamscan not installed"
    exit 1
fi

unixclamdb="${SPLUNK_HOME}/etc/apps/clamnix/unixclamdb"
if [[ ! -d "$unixclamdb" ]]
then
    echo "FAILURE: unable to find unixclamdb at $unixclamdb"
    exit 1
fi

# startup sleep for server farms sharing disk
# $RANDOM can equal 0, so always add 1
octet=$(ip addr ls|grep ' inet '|grep -v 127.0.0.1|head -1 |awk '{print $2}' |cut -d'.' -f4 |cut -d'/' -f1)
maxtime=1209600
octdiff=$(( ( maxtime / 256 ) / 2 ))
if [[ $octet -ge 0 ]] \
&& [[ $octet -le 255 ]] \
&& [[ $octet =~ ^[[:digit:]]+$ ]]
then
    sleeptime=$(( 
        ( ( maxtime / 256 ) * octet )
        + ( ( (RANDOM + octdiff) * (RANDOM + octdiff) ) % octdiff ) 
        - ( ( (RANDOM + octdiff) * (RANDOM + octdiff) ) % octdiff ) 
    ))
    if [[ $sleeptime -le 0 ]]
    then
        sleeptime=$(( (RANDOM + octdiff) * (RANDOM + octdiff)  % octdiff ))
        echo "sleeptime=\"$sleeptime\" reason=\"octet $octet but fell below 1\""
    else 
        echo "sleeptime=\"$sleeptime\" reason=\"octet $octet\""
    fi
else
    sleeptime=$(( ( (RANDOM + octdiff) * (RANDOM + octdiff) * (RANDOM + octdiff) ) % maxtime ))
    echo "sleeptime=\"$sleeptime\" reason=\"random\""
fi

echo "starttime=\"$(date)\" sleeptime=\"$sleeptime\""
sleep $sleeptime
startepoch=$(date +%s)

nice 20 $$ >/dev/null 2>&1
ionice -c3 -p $$ >/dev/null 2>&1


for dir in /usr/bin /usr/lib /usr/libexec /usr/lib32 /usr/lib64 /usr/local/bin /usr/local/sbin /usr/local/lib /usr/local/lib64 /usr/local/libexec /usr/sbin /tmp /var/tmp /dev/shm
do
    if [[ -d $dir ]]
    then
        dirs[${#dirs[@]}]="$dir"
    fi
done
if ! stat /bin|grep -q 'symbolic link'
then
    dirs[${#dirs[@]}]="$dir"
fi
if ! stat /sbin|grep -q 'symbolic link'
then
    dirs[${#dirs[@]}]="$dir"
fi

IFS='
'

for line in $(clamscan -d "$unixclamdb" --scan-pe=no --scan-ole2=no --scan-pdf=no --scan-swf=no --scan-html=no --scan-archive=no --max-filesize=10M --scan-mail=no --phishing-sigs=no --phishing-scan-urls=no --follow-dir-symlinks=0 --follow-file-symlinks=0 --cross-fs=no -o -i -r "${dirs[@]}" 2>/dev/null)
do
    if [[ $line =~ FOUND$ ]]
    then
        found=${line##*: }
        echo "file=\"${line%%: *}\" virus=\"${found%% FOUND}\""
    elif [[ $line =~ "Known viruses:" ]]
    then
        summary[${#summary[@]}]="KnownViruses=\"${line##*: }\""
    elif [[ $line =~ "Engine version:" ]]
    then
        summary[${#summary[@]}]="EngineVersion=\"${line##*: }\""
    elif [[ $line =~ "Scanned files:" ]]
    then
        summary[${#summary[@]}]="ScannedFiles=\"${line##*: }\""
    elif [[ $line =~ "Infected files:" ]]
    then
        summary[${#summary[@]}]="InfectedFiles=\"${line##*: }\""
    elif [[ $line =~ "Data scanned:" ]]
    then
        summary[${#summary[@]}]="DataScanned=\"${line##*: }\""
    elif [[ $line =~ "Data read:" ]]
    then
        summary[${#summary[@]}]="DataRead=\"${line##*: }\""
    elif [[ $line =~ "Time:" ]]
    then
        summary[${#summary[@]}]="Time=\"${line##*: }\""
    fi
done

# If the summary array is empty, then the scan failed to run.
if [[ ${#summary[@]} == 0 ]]
then
    echo "FAILURE: clamscan failed to run"
else
    echo "${summary[@]}"
fi


#----------- SCAN SUMMARY -----------
#Known viruses: 181294
#Engine version: 0.99.2
#Scanned directories: 1
#Scanned files: 1710
#Infected files: 0
#Data scanned: 293.03 MB
#Data read: 405.91 MB (ratio 0.72:1)
#Time: 10.076 sec (0 m 10 s)
#


if [[ -f "$unixclamdb"/main.info ]] \
&& [[ -f "$unixclamdb"/daily.info ]]
then
    maindate=$(egrep '^ClamAV-VDB:' "$unixclamdb"/main.info |cut -d':' -f2)
    dailydate=$(egrep '^ClamAV-VDB:' "$unixclamdb"/daily.info |cut -d':' -f2)
    echo "maindate=\"$maindate\" dailydate=\"$dailydate\""
else
    echo "FAILURE: Unable to find main.info and daily.info"
fi


endepoch=$(date +%s)
runtime=$(( endepoch - startepoch ))
runhour=$(( runtime / 3600 ))
runmin=0$(( (runtime - ( runhour * 3600 )) / 60 ))
runmin=${runmin:$((${#runmin}-2)):${#runmin}}
runsec=0$(( (runtime - ( runhour * 3600 )) % 60 ))
runsec=${runsec:$((${#runsec}-2)):${#runsec}}
echo "endtime=\"$(date)\" endepoch=\"$endepoch\" sleeptime=\"$sleeptime\" runtimesec=\"$runtime\" runtime=\"${runhour}:${runmin}:${runsec}\" result=\"complete\""
