#!/bin/sh
##
## Based on suricata_log by @juched
## Process logs into SQLite3 for stats generation
## snort_log.sh
readonly SCRIPT_VERSION="v1.0"

Say(){
   echo -e $$ $@ | logger -st "($(basename $0))"
}

ScriptHeader(){
	printf "\\n"
	printf "##\\n"
	printf "##Snort Log\\n"
	printf "## Process logs into SQLite3 for stats generation - %s                      \\n" "$SCRIPT_VERSION"
	printf "\\n"
	printf "snort_log.sh\\n"
}

ScriptHeader

# default to non-syslog location and variable positions
snort_csv="/opt/var/log/alert_csv.txt"

echo "Logfile used is $snort_csv"

#other variables
tmpSQL="/tmp/snort_log.sql"
dbLogFile="/opt/etc/snort/snort_log.db"
dateString=$(date '+%F')
olddateString30=$(date -D %s -d $(( $(date +%s) - 30*86400)) '+%F')
echo "Date used is $dateString (30 days ago is $olddateString30)"

#create table to track threats detected from fast.log
echo "Creating threat_log table if needed..."
printf "CREATE TABLE IF NOT EXISTS [threat_log] ([threat_id] VARCHAR(32) NOT NULL,[threat_desc] VARCHAR(255) NOT NULL,[threat_class] VARCHAR(255) NOT NULL, [threat_priority] VARCHAR(32) NOT NULL, [threat_src_ip] VARCHAR(16) NOT NULL, [threat_dst_ip] VARCHAR(16) NOT NULL, [date] DATE NOT NULL, [count] INTEGER NOT NULL, PRIMARY KEY(threat_id,date));" | sqlite3 $dbLogFile

#delete old records > 30 days ago
echo "Deleting old threat_log records older than 30 days..."
printf "DELETE FROM threat_log WHERE date < '$olddateString30';" | sqlite3 $dbLogFile


# Add to SQLite all reply domains (log-replies must be yes)
if [ -f "$snort_csv" ]; then # only if log exists
  echo "Processing..."
  # process reply logs - for top daily replies table
  echo "BEGIN;" > $tmpSQL
  cat $snort_csv | tr -d ' ' | awk -F',' '{ printf "INSERT OR IGNORE INTO threat_log ([threat_id],[threat_desc],[threat_class],[threat_priority],[threat_src_ip],[threat_dst_ip],[date],[count]) VALUES (\x27%s\x27, \x27%s\x27, \x27%s\x27, \x27%s\x27, \x27%s\x27, \x27%s\x27, \x27%s\x27, 0);\n",$1,$2,$3,$4,$5,$6,$7;printf "UPDATE threat_log SET count = count + 1 WHERE threat_id = \x27%s\x27 AND threat_src_ip = \x27%s\x27 AND threat_dst_ip = \x27%s\x27 AND date = \x27%s\x27;\n",$1,$2,$3,$4}' >> $tmpSQL
  echo "COMMIT;" >> $tmpSQL

  # log out the processed nodes
  threat_count=$(wc -l $snort_csv|cut -f1 -d' ')
  Say "Processed $threat_count threat records..."

  #echo "Removing threat lines from log file..."
  sed -i '/,/d' $snort_csv

  # HUP to restart logs
  /opt/etc/init.d/S81Snort3 restart 2>/dev/null

  echo "Running SQLite to import new reply records..."
  sqlite3 $dbLogFile < $tmpSQL

  #cleanup
  if [ -f $tmpSQL ]; then rm $tmpSQL; fi

fi

echo "All done!"
