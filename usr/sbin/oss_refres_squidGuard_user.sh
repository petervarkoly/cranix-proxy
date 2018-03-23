#!/bin/bash
dbHome="/var/lib/squidGuard/db/"

for p in $( oss_api_text.sh GET groups/text/byType/primary )
do
    /usr/sbin/oss_api_text.sh GET groups/text/$p/members > $dbHome/$p
done

systemctl restart squid

