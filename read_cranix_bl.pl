#!/usr/bin/perl
use strict;
use Data::Dumper;
my $NAME='';
my $LISTS={};
my @BL=();
my @WL=();
my $LANGS={};

system("rm -f cranix-blacklists.txz");
system("wget http://repo.cephalix.eu/cranix-blacklists.txz");
system("tar xf cranix-blacklists.txz");
open(INP,"BL/global_usage");
while(<INP>)
{
        next if (/^#/);
        chomp;
        if(/^NAME:\s+(.*)/)
        {
           $NAME=$1;
           $NAME=~s#/#-#;
        }
        elsif(/^NAME (..):\s+(.+)$/)
        {
                $LISTS->{$NAME}->{NAME}->{$1} = $2;
                $LANGS->{$1} = 1 if ( $1 ne 'RU' );
        }
        elsif(/^DESC (..):\s+(.+)$/)
        {
                $LISTS->{$NAME}->{DESC}->{$1} = $2;
        }
        elsif(/^DEFAULT_TYPE:\s+(.+)$/)
        {
                $LISTS->{$NAME}->{TYPE} = $1;
        }
}
print Dumper($LISTS);
close(INP);

foreach my $L (keys %$LANGS)
{
    foreach my $i (keys %$LISTS)
    {
        if( $L eq 'DE' )
        {
                if( $LISTS->{$i}->{TYPE} eq 'black' )
                {
                        push @BL, $i;
                }
                else
                {
                        push @WL, $i;
                }
        }
    }
}
close LANG;
open(OUT,">usr/share/cranix/templates/blacklists");
print OUT join "\n",sort(@BL);
close OUT;
open(OUT,">usr/share/cranix/templates/whitelists");
print OUT join "\n",sort(@WL);
close OUT;
system("rm -rf BL");
system("mv cranix-blacklists.txz var/lib/squidGuard/db");

