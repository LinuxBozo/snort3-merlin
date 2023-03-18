#! /bin/sh
curl --progress-bar -SL https://www.snort.org/downloads/community/snort3-community-rules.tar.gz | tar -zxC /opt/etc/snort/rules/
sleep 2s
/opt/etc/init.d/S81snort3 stop
sleep 2s
/opt/etc/init.d/S81snort3 start
