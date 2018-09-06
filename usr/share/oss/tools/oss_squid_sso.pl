#!/usr/bin/perl

$| = 1; # do not buffer stdout

while(<STDIN>) {
        chomp;
        my $user = `curl -sX GET --header 'Content-Type: application/json' --header 'Accept: text/plain' http://localhost:9080/api/devices/loggedIn/$_`;
        if ( "$user" ) {
                print "OK user=\"$user\"\n";
        }
        else
        {
                print "OK user=\"default user\"\n";
        }
}

