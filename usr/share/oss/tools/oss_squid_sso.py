#!/usr/bin/python3
import os

while True:
    ip=input("")
    user = os.popen("curl -sX GET --header 'Content-Type: application/json' --header 'Accept: text/plain' http://localhost:9080/api/devices/loggedIn/" + ip ).read()
    if user == "":
        print('OK user="default_user"')
    else:
        print('OK user="' + user + '"')

