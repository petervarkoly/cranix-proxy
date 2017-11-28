#!/usr/bin/perl
use strict;
use Data::Dumper;


system("wget http://www.shallalist.de/Downloads/shallalist.tar.gz");
system("tar xzf shallalist.tar.gz");
open(SHALLA,"BL/global_usage");
my $NAME='';
my $SHALLA={};
my @BL=();
my @WL=();
my $LANGS={};
my $TRANS= {
		'DE' => {  
				DESC => {
						bad        => 'Eigene Blackliste',
						good       => 'Eigene Whiteliste',
						'in-addr'  => 'IP-Adressen',
						all        => 'Alle andere Domains'
				},
				bad        => 'Blackliste',
				good       => 'Whiteliste',
				'in-addr'  => 'IP-Adressen',
				all        => 'Der Rest'
			},
		'EN' => {  
				DESC => {
						bad        => 'Own Blacklist',
						good       => 'Own Whitelist',
						'in-addr'  => 'IP-Addresses',
						all        => 'All other domains'
				},
				bad        => 'Blacklist',
				good       => 'Whitelist',
				'in-addr'  => 'IP-Addresses',
				all        => 'The Rest'
			}

				
	   };

while(<SHALLA>)
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
		$SHALLA->{$NAME}->{NAME}->{$1} = $2;
		$LANGS->{$1} = 1 if ( $1 ne 'RU' );
	}
	elsif(/^DESC (..):\s+(.+)$/)
	{
		$SHALLA->{$NAME}->{DESC}->{$1} = $2;
	}
	elsif(/^DEFAULT_TYPE:\s+(.+)$/)
	{
		$SHALLA->{$NAME}->{TYPE} = $1;
	}
}
print Dumper($SHALLA);
close SHALLA;
open(LANG,">usr/share/oss/templates/squidguard_lang.sql");
foreach my $L (keys %$LANGS)
{
    for my $i ( 'good', 'bad', 'all', 'in-addr' )
    {
	    if( $TRANS->{$L}->{$i} )
	    {
		print LANG "INSERT INTO Translations VALUES(NULL,'$L','$i','".$TRANS->{$L}->{$i}."');\n";
		my $desc = $TRANS->{$L}->{DESC}->{$i};
		$desc =~ s/'/\\'/;
		print LANG "INSERT INTO Translations VALUES(NULL,'$L','$i-DESC','$desc');\n";
	    }
    }
    foreach my $i (keys %$SHALLA)
    {
	if( defined $SHALLA->{$i}->{NAME}->{$L} )
	{
		my $desc = $SHALLA->{$i}->{NAME}->{$L};
		$desc =~ s/'/\\'/;
		print LANG "INSERT INTO Translations VALUES(NULL,'$L','$i','$desc');\n";
	}
	if( defined $SHALLA->{$i}->{DESC}->{$L} )
	{
		my $desc = $SHALLA->{$i}->{DESC}->{$L};
		$desc =~ s/'/\\'/;
		print LANG "INSERT INTO Translations VALUES(NULL,'$L','$i-DESC','$desc');\n";
	}
	if( $L eq 'DE' )
	{
		if( $SHALLA->{$i}->{TYPE} eq 'black' )
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
open(OUT,">usr/share/oss/templates/blacklists");
print OUT join "\n",sort(@BL);
close OUT;
open(OUT,">usr/share/oss/templates/whitelists");
print OUT join "\n",sort(@WL);
close OUT;
system("rm -rf BL");
system("mv shallalist.tar.gz var/lib/squidGuard/db"); 
