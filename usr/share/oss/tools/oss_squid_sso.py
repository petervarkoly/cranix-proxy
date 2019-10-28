#!/usr/bin/python3

import requests

while True:
    ip=input("")
    user = requests.get('http://localhost:9080/api/devices/loggedIn/' + ip.strip()).text
    if user == "":
        print('OK user="default_user"')
    else:
        print('OK user="' + user + '"')

