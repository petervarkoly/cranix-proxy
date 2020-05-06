#!/bin/bash
dbHome="/var/lib/squidGuard/db/"

for p in $( crx_api_text.sh GET groups/text/byType/primary )
do
    /usr/sbin/crx_api_text.sh GET groups/text/$p/members > $dbHome/$p
done

systemctl restart squid

