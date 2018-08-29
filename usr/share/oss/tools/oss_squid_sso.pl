#!/usr/bin/perl

while(<STDIN>) {
        chomp;
        my $user = `curl -sX GET --header 'Content-Type: application/json' --header 'Accept: text/plain' http://localhost:9080/api/devices/loggedIn/$_`;
        if ( "$user" ) {
                print "OK user=\"$user\"\n";
        }
        else
        {
                print "ERR user=\"No user logged in\"\n";
        }
}

