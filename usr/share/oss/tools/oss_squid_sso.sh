#!/bin/bash

TOKEN=$( grep de.openschoolserver.api.auth.localhost= /opt/oss-java/conf/oss-api.properties | sed 's/de.openschoolserver.api.auth.localhost=//' )

while true
do
        read IP
        user=$( curl -sX GET --header 'Content-Type: application/json' --header 'Accept: text/plain' $DATA --header 'Authorization: Bearer '${TOKEN} "http://localhost:9080/api/devices/loggedIn/$IP" )
	if [ "$user" ];
	then
		echo "OK user=\"$user\""
	else
		echo "OK user=\"default user\""
	fi
done
