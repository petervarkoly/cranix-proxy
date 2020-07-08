#!/usr/bin/perl
use strict;
use Data::Dumper;
use JSON::XS;
use Types::Serialiser;
use vars qw(@ISA);

my $conffile = '/etc/squid/squidguard.conf';
my $bin      = '/usr/sbin/squidGuard';

my $job=shift;
my $NAME=shift || 'default';

my @Sources = ();
my @Destinations = ();
my @listsToRemove = ();

sub readRoomSetting
{
	my $room   = shift;
	my $source = "";
	my $config = parse_config();
	my $acls   = find_section($config,{ sectype => 'acl' });
	my $allAllowed = {};
	my $reply      = {};
	my @ACLS = ();
        foreach my $acl (@{$acls->{members}})
        {
		$source =  $acl->{source};
		next if ( $source ne $room );
		foreach my $pass ( @{$acl->{pass}} )
		{
			next if $pass eq 'none';
			push @ACLS,$pass;
		}
        }
	print join(" ",@ACLS)."\n";
}

sub readSetting {
	my $config = parse_config();
	my $acls   = find_section($config,{ sectype => 'acl' });
	my $srcs   = find_sections_by_type($config,'source');
	$srcs->{default} = 1;
	my $reply      = {};
        foreach my $acl (@{$acls->{members}})
        {
		my $source =  $acl->{source};
		foreach my $pass ( @{$acl->{pass}} )
		{
			if( $pass =~ /!(.*)/ ) {
				$reply->{acls}->{$source}->{$1} = "false";
			} else {
				$reply->{acls}->{$source}->{$pass} = "true";
			}
		}
		if( ! defined $reply->{acls}->{$source}->{all} ) {
			$reply->{acls}->{$source}->{all} = "false";
		}
        }
	my @primaries = `crx_api_text.sh GET groups/text/byType/primary`;
	push @primaries, 'default';
	foreach my $source ( @primaries ) {
		chomp $source;
		next if( $source =~ /^templates$/ );
		next if( ! defined $srcs->{$source} );
		my @ACLS = ($source);
		foreach my $pass ( get_lists() ) {
			chomp $pass;
			if( defined $reply->{acls}->{$source}->{$pass} ) { 
				push @ACLS, "$pass:".$reply->{acls}->{$source}->{$pass};
			} else {
				push @ACLS, "$pass:".$reply->{acls}->{$source}->{all};
			}
		}
		print join(" ",@ACLS)."\n";
	}
}

sub jsonSetting {
	my $config = parse_config();
	my $acls   = find_section($config,{ sectype => 'acl' });
	my $srcs   = find_sections_by_type($config,'source');
	$srcs->{default} = 1;
	my $reply = {};
	my @array = ();
        foreach my $acl (@{$acls->{members}})
        {
		my $source =  $acl->{source};
		foreach my $pass ( @{$acl->{pass}} )
		{
			if( $pass =~ /!(.*)/ ) {
				$reply->{acls}->{$source}->{$1} = Types::Serialiser::false;
			} else {
				$reply->{acls}->{$source}->{$pass} = Types::Serialiser::true;
			}
		}
		if( ! defined $reply->{acls}->{$source}->{all} ) {
			$reply->{acls}->{$source}->{all} = Types::Serialiser::false;
		}
        }
	my @primaries = `crx_api_text.sh GET groups/text/byType/primary`;
	push @primaries, 'default';
	foreach my $pass ( get_lists() ) {
		next if( $pass =~ /^cephalix|good|bad$/ );
		chomp $pass;
		my $acl = {};
		$acl->{'name'} = $pass;
		foreach my $source ( @primaries ) {
			chomp $source;
			next if( $source =~ /^templates$/ );
			next if( ! defined $srcs->{$source} );
			if( defined $reply->{acls}->{$source}->{$pass} ) {
				$acl->{$source} = $reply->{acls}->{$source}->{$pass};
			} else {
				$acl->{$source} = $reply->{acls}->{$source}->{all};
			}
		}
		push @array,$acl; 
	}
	#print Dumper(\@array);
	print encode_json(\@array);	
}

sub printAll {
	my $config = parse_config();
	print Dumper($config);
	
}

#################################################################
#
# Writes the configuration
#
################################################################
sub apply
{
	my $reply = shift;
	my %acls  = ();
	my $srcWritten = 0;
	my $aclWritten = 0;
	my $dbHome     = "/var/lib/squidGuard/db";
	my @primaries = `crx_api_text.sh GET groups/text/byType/primary`;
	push @primaries, 'default';
	my @DefinedSources = ();
	my $config = parse_config();
	my $srcs   = find_sections_by_type($config,'source');
	$srcs->{default} = 1;
	foreach my $acl (get_lists())
	{
		chomp $acl;
		if( $acl eq 'all' )
		{
			foreach my $p ( @primaries )
			{
				chomp $p;
				next if( $p =~ /^templates$/ );
				next if( ! defined $srcs->{$p} );
				push @{$acls{$p}}, ($reply->{acls}->{$p}->{$acl} eq "true" ) ? 'all' : 'none';
			}
		}
		else
		{
			foreach my $p ( @primaries )
			{
				chomp $p;
				next if( $p =~ /^templates$/ );
				next if( ! defined $srcs->{$p} );
				push @{$acls{$p}}, ($reply->{acls}->{$p}->{$acl} eq "true" ) ? $acl : "!$acl";
			}
		}
	}	
	# Now we save the squidquard config file
 	open SG, ">$conffile";
	foreach my $sec ( @$config )
	{
		if( $sec->{sectype} eq 'logdir' )
		{
			print SG 'logdir '.$sec->{logdir}."\n";
		}
		elsif( $sec->{sectype} eq 'dbhome' )
		{
			print SG 'dbhome '.$sec->{dbhome}."\n";
		}
		elsif( $sec->{sectype} eq 'source' )
		{
			if(!$srcWritten and defined $reply->{source}) {
				my $newSource = $reply->{source};
				print SG "src $newSource {\n\t".$reply->{sourcetype}." $newSource\n}\n\n";
			}
			#TODO at the moment we only can handle userlist type sources
			if( defined $sec->{members}->[0]->{userlist} ) {
				my $p = $sec->{members}->[0]->{userlist};
				print SG "src $p {\n\tuserlist $p\n}\n\n";
			} elsif( defined $sec->{members}->[0]->{iplist} ) {
				my $p = $sec->{members}->[0]->{iplist};
				print SG "src $p {\n\tiplist $p\n}\n\n";
			}
			$srcWritten = 1;
		}
		elsif( $sec->{sectype} eq 'dest' )
		{
			next if(grep(/$sec->{secname}/,@listsToRemove));
			print SG 'dest '.$sec->{secname}." {\n";
			print SG "\tdomainlist ".$sec->{domainlist}."\n"    if ( defined $sec->{domainlist} );
			print SG "\turllist    ".$sec->{urllist}."\n"       if ( defined $sec->{urllist} );
			print SG "\texpressionlist ".$sec->{exprlist}."\n"  if ( defined $sec->{exprlist} );
			print SG "\tlog        ".$sec->{'log'}."\n"         if ( defined $sec->{'log'} );
			print SG "}\n\n";
		}
		elsif( $sec->{sectype} eq 'acl' )
		{
			if( defined $reply->{destination} && !$aclWritten ) {
				print SG 'dest '.$reply->{destination}." {\n";
				print SG "\tdomainlist PL/".$reply->{destination}."/domains\n";
				print SG "}\n\n";
			}
			print SG "acl {\n" if( !$aclWritten );
			$aclWritten = 1;
			#First we writes the non rimary group acls
			foreach my $acl (@{$sec->{members}}) {
				my $source =  $acl->{source};	
				push @DefinedSources, $source;
				#This will be written at the end
				next if( grep(/$source/,@primaries) );
				#This source should be deleted
				next if( defined $reply->{acls}->{$source}->{'remove-this-list'} );
				my @ACLS = ();
				foreach my $key ( keys %{$reply->{acls}->{$source}} ) {
					next if($key eq 'all');
					#This acl will be removed
					next if(grep(/$key/,@listsToRemove));
					push @ACLS, $reply->{acls}->{$source}->{$key} eq "true" ? $key : "!$key";
				}
				if( defined $reply->{acls}->{$source}->{all} ) {
					push @ACLS, $reply->{acls}->{$source}->{all} eq "true" ? 'all' : 'none';
				}
				print SG "\t$source {\n";
				print SG "\t\tpass ".join(" ",@ACLS)."\n";
				print SG "\t\tredirect ".'302:http://admin/cgi-bin/cranix-stop.cgi/?clientaddr=%a&clientname=%n&clientident=%i&srcclass='.$source.'&targetclass=OSSPositiveList&url=%u'."\n";
				print SG "\t}\n";
			}
		}
	}
	#Now we are searching for new sources
	foreach my $source ( keys %{$reply->{acls}} ) {
		next if( grep(/$source/, @DefinedSources ));
		next if( defined $reply->{acls}->{$source}->{'remove-this-list'} );
		my @ACLS = ();
		foreach my $key ( keys %{$reply->{acls}->{$source}} ) {
			next if($key eq 'all');
			push @ACLS, $reply->{acls}->{$source}->{$key} eq "true" ? $key : "!$key";
		}
		if( defined $reply->{acls}->{$source}->{all} ) {
			push @ACLS, $reply->{acls}->{$source}->{all} eq "true" ? 'all' : 'none';
		} else {
			push @ACLS, 'none';
		}
		print SG "\t$source {\n";
		print SG "\t\tpass ".join(" ",@ACLS)."\n";
		print SG "\t\tredirect ".'302:http://admin/cgi-bin/cranix-stop.cgi/?clientaddr=%a&clientname=%n&clientident=%i&srcclass='.$source.'&targetclass=OSSPositiveList&url=%u'."\n";
		print SG "\t}\n";
	}
	foreach my $p ( @primaries )
	{
		chomp $p;
		next if( $p =~ /^templates$/ );
		next if( ! defined $acls{$p} );
		if( $p eq 'default' )
		{
			print SG "\t$p {\n";
			print SG "\t\tpass ".join(" ",@{$acls{$p}})."\n";
			#print SG "\t\tredirect ".'302:https://admin/?clientaddr=%a&clientname=%n&clientident=%i&srcclass='.$p.'&targetclass=%t&url=%u'."\n";
			print SG "\t\tredirect ".'302:https://admin/'."\n";
			print SG "\t}\n";
		}
		else
		{
			print SG "\t$p {\n";
			print SG "\t\tpass ".join(" ",@{$acls{$p}})."\n";
			print SG "\t\tredirect ".'302:http://admin/cgi-bin/cranix-stop.cgi/?clientaddr=%a&clientname=%n&clientident=%i&srcclass='.$p.'&targetclass=%t&url=%u'."\n";
			print SG "\t}\n";
		}
	}
	print SG "}\n\n";
	close SG;
	sgchown();
	if( $job ne "writeIpSource" && $job ne "writeUserSource") {
	    system("/usr/sbin/crx_refresh_squidGuard_user.sh");
	}
}

sub get_lists
{
	open(IN,"/usr/share/cranix/templates/blacklists");
	my @BL = <IN>;
	close(IN);
	#@BL = main::sort_by_lang(\@BL);
	open(IN,"/usr/share/cranix/templates/whitelists");
	my @WL = <IN>;
	close(IN);
	#@WL = main::sort_by_lang(\@WL);
	my @LISTS = ('cephalix','good','bad','in-addr');
        push @LISTS, @WL,@BL,'all';
	return @LISTS;
}

############## Helper funktions from webmin #########
#    SquidGuard Configuration Webmin Module Library
#    Copyright (C) 2001 by Tim Niemueller <tim@niemueller.de>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    Created  : 26.03.2001
#    Modified by Peter Varkoly : 21.05.2009

my $_DEBUG=0;

sub parse_config {

  # Do NOT use read_file_lines here, otherwise a
  # flush_file_lines in save_*.cgi would have
  # Very Bad Side-Effects (TM)

  open(CONF, $conffile);
    my @c=<CONF>;
  close(CONF);
  my @config=();
  my $counter = 0;

  for (my $i=0; $i < @c; $i++) {
    $c[$i] = unify($c[$i]);

    next if (!$c[$i] || ($c[$i] =~ /^#/));
    print "$i: $c[$i]<BR>\n" if $_DEBUG;

    if ($c[$i] =~ /^dbhome\s+(\S+)/) {

      ###### DB Home

      my %section;
	 $section{'counter'}=$counter++;
         $section{'sectype'}='dbhome';
         $section{'dbhome'}=$1;
         $section{'line'}=$i;

      print "<B>dbhome token found (i: $i, dbhome: $section{'dbhome'})</B><BR>\n" if $_DEBUG;

      push(@config, \%section);

    } elsif ($c[$i] =~ /^logdir\s+(\S+)/) {

      ###### Log Dir

      my %section;
	 $section{'counter'}=$counter++;
         $section{'sectype'}='logdir';
         $section{'logdir'}=$1;
         $section{'line'}=$i;

      print "<B>logdir token found (i: $i, logdir: $section{'logdir'})</B><BR>\n" if $_DEBUG;

      push(@config, \%section);

    } elsif ($c[$i] =~ /^time\s+([-_.a-zA-Z0-9]+)\s+\{\s*$/) {

      ###### Timespace

      my %section;
	 $section{'counter'}=$counter++;
         $section{'sectype'}='time';
         $section{'secname'}=$1;
         $section{'line'}=$i;

      my @members=();
      $c[$i] = unify($c[++$i]);
      while(($i < scalar(@c)) && ($c[$i] !~ /^\s*\}/)) {
        $c[$i] = unify($c[$i]);
        if ( ($c[$i] =~ /^weekly\s(.*)\s(\d\d:\d\d\s?-\s?\d\d:\d\d)/) ||
             ($c[$i] =~ /^weekly\s(.*)/) ) {
          print "<B>weekly token found</B><BR>\n" if $_DEBUG;
          my %st;
             $st{'stype'} = 'weekly';
             $st{'time'} = $2;
             $st{'line'} = $i;
             $st{'rawdays'} = $1;

          $st{'time'} =~ s/\s//g;
          my ($from, $to) = split(/-/, $st{'time'}, 2);
          ($st{'shour'}, $st{'smin'}) = split(/:/, $from);
          ($st{'ehour'}, $st{'emin'}) = split(/:/, $to);

          my @r=split(/\s?/, $st{'rawdays'});
          my $d='';
          foreach my $s (@r) {
            print "S: $s<BR>\n" if $_DEBUG;
            if ($s eq '*') {
              $d='*';        # 128
              last;
            } elsif ($s =~ /m(ondays?)?/) {
              $d.='m';       # ++
            } elsif ($s =~ /t(uesdays?)?/) {
              $d.='t';       ## +=2;
            } elsif ($s =~ /w(ednesdays?)?/) {
              $d.='w';       ## +=4;
            } elsif ($s =~ /t?h(ursdays?)?/) {
              $d.='h';       ## +=8;
            } elsif ($s =~ /f(ridays?)?/) {
              $d.='f';       ## +=16;
            } elsif ($s =~ /s?a(turdays?)?/) {
              $d.='a';       ## +=32;
            } elsif ($s =~ /s(undays?)?/) {
              $d.='s';       ## +=64;
            }
          }
          $st{'days'}=$d;
          push(@members, \%st);
        } elsif ( ($c[$i] =~ /^date\s+(\d\d\d\d|\*)[.-](\d\d|\*)[.-](\d\d|\*)\s*(\d\d:\d\d\s?-\s?\d\d:\d\d)/) ) {
          #        ($c[$i] =~ /^date\s (\d\d|\*)[.-](\d\d|\*)[.-](\d\d|\*)/) ) {
          # 
          print "<B>date token found - 1</B><BR>\n" if $_DEBUG;
          my %st;
          $st{'stype'}='date';
          $st{'line'} = $i;
          $st{'syear'}=$1;
          $st{'syear'}+=2000 if (length($st{'syear'}==2));
          $st{'smonth'}=$2;
          $st{'sday'}=$3;
          $st{'time'}=$4;

          $st{'time'} =~ s/\s//g;
          my ($from, $to) = split(/-/, $st{'time'}, 2);
          ($st{'shour'}, $st{'smin'}) = split(/:/, $from);
          ($st{'ehour'}, $st{'emin'}) = split(/:/, $to);

          push(@members, \%st);

       } elsif (($c[$i] =~ /^date\s+(\d\d\d\d|\*)[.-](\d\d|\*)[.-](\d\d|\*)-(\d\d\d\d|\*)[.-](\d\d|\*)[.-](\d\d|\*)\s*(\d\d:\d\d\s?-\s?\d\d:\d\d)/) ||
                ($c[$i] =~ /^date\s+(\d\d\d\d|\*)[.-](\d\d|\*)[.-](\d\d|\*)-(\d\d\d\d|\*)[.-](\d\d|\*)[.-](\d\d|\*)/) ) {
          print "<B>date range token found (l: $i, i: ", scalar(@members), ")</B><BR>\n" if $_DEBUG;
          my %st;
          $st{'stype'}='date_range';
          $st{'line'} = $i;
          $st{'syear'}=$1;
          $st{'smonth'}=$2;
          $st{'sday'}=$3;
          $st{'eyear'}=$4;
          $st{'emonth'}=$5;
          $st{'eday'}=$6;
          $st{'time'}=$7;

          $st{'time'} =~ s/\s//g;
          my ($from, $to) = split(/-/, $st{'time'}, 2);
          ($st{'shour'}, $st{'smin'}) = split(/:/, $from);
          ($st{'ehour'}, $st{'emin'}) = split(/:/, $to);

          push(@members, \%st);

        }
        $i++;
      } # End of while

      # All empty lines after the section
      # are counted to the section
      while (($i+1 < scalar(@c)) && (unify($c[$i+1]) eq "")) {
        $i++;
        $c[$i] = unify($c[$i]);
      }
      $section{'end_line'} = $i;

      $section{'members'}=\@members;
      push(@config, \%section);
    } elsif ($c[$i] =~ /^(src|source)\s+([-_.a-zA-Z0-9]+)\s+((within|outside)\s+([-_.a-zA-Z0-9]+)\s+)?\{\s*$/) {

      ###### Source Group

      print "<B>source token found ($i)</B><BR>\n" if $_DEBUG;
      my %section;
	 $section{'counter'}=$counter++;
         $section{'sectype'}='source';
         $section{'secname'}=$2;
         $section{'line'}=$i;
         $section{'tstype'} = $4;
         $section{'timespace'} = $5;
      push @Sources, $2;

      my @members=();

      $c[$i] = unify($c[++$i]);
      while(($i < scalar(@c)) && ($c[$i] !~ /^\s*\}/)) {
        $c[$i] = unify($c[$i]);

        if ($c[$i] =~ /^ip\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
          my %st;
             $st{'stype'}='subnet_long';
             $st{'line'}=$i;
             $st{'ip'}=$1;
             $st{'mask'}=$2;
          push(@members, \%st);
        } elsif ($c[$i] =~ /^ip\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
          my %st;
             $st{'stype'}='iprange';
             $st{'line'}=$i;
             $st{'ip'}=$1;
             $st{'end'}=$2;
          push(@members, \%st);
        } elsif ($c[$i] =~ /^ip\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d\d?)/) {
          my %st;
             $st{'stype'}='subnet';
             $st{'line'}=$i;
             $st{'ip'}=$1;
             $st{'prefix'}=$2;
          push(@members, \%st);
        } elsif ($c[$i] =~ /^ip\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
          my %st;
             $st{'stype'}='ip';
             $st{'line'}=$i;
             $st{'ip'}=$1;
          push(@members, \%st);


        } elsif ($c[$i] =~ /^domain\s+(\S+)/) {
          my %st;
             $st{'stype'}='domain';
             $st{'line'}=$i;
             $st{'domain'}=$1;
          push(@members, \%st);

        } elsif ($c[$i] =~ /^user\s+(\S+)/) {
          my %st;
             $st{'stype'}='user';
             $st{'line'}=$i;
             $st{'user'}=$1;
          push(@members, \%st);
        } elsif ($c[$i] =~ /^iplist\s+(\S+)/) {
          my %st;
             $st{'stype'}='iplist';
             $st{'line'}=$i;
             $st{'iplist'}=$1;
             $st{'iplist'} =~ /\/?([^\/]+)$/;
             $st{'name'}=$1;
          push(@members, \%st);
        } elsif ($c[$i] =~ /^userlist\s+(\S+)/) {
          my %st;
             $st{'stype'}='userlist';
             $st{'line'}=$i;
             $st{'userlist'}=$1;
             $st{'userlist'} =~ /\/?([^\/]+)$/;
             $st{'name'}=$1;
          push(@members, \%st);
        } elsif ($c[$i] =~ /^execuserlist\s+(.*)/) {
          my %st;
             $st{'stype'}='execuserlist';
             $st{'line'}=$i;
             $st{'execuserlist'}=$1;
          push(@members, \%st);
        }

        $i++;
      }

      # All empty lines after the section
      # are counted to the section
      while (($i+1 < scalar(@c)) && (unify($c[$i+1]) eq "")) {
        $i++;
        $c[$i] = unify($c[$i]);
      }
      $section{'end_line'} = $i;

      $section{'members'}=\@members;
      push(@config, \%section);
    } elsif ($c[$i] =~ /^(dest|destination)\s+([-_.a-zA-Z0-9]+)(\s+(within|outside)\s+([-_.a-zA-Z0-9]+))?\s+\{\s*$/) {

      ###### destination group

      print "<B>destination token found ($i)</B><BR>\n" if $_DEBUG;
      my %section;
	 $section{'counter'}=$counter++;
         $section{'sectype'}='dest';
         $section{'secname'}=$2;
         $section{'line'}=$i;
         $section{'tstype'}=$4;
         $section{'timespace'}=$5;
      push @Destinations, $2;

      $c[$i] = unify($c[++$i]);
      while(($i < scalar(@c)) && ($c[$i] !~ /^\s*\}/)) {
        $c[$i] = unify($c[$i]);

        if ($c[$i] =~ /^domainlist\s+(\S+)/) {
          $section{'domainlist'}=$1;
          $section{'domainlist_line'} = $i;
        } elsif ($c[$i] =~ /^urllist\s+(\S+)/) {
          $section{'urllist'}=$1;
          $section{'urllist_line'} = $i;
        } elsif ($c[$i] =~ /^expressionlist\s+(\S+)/) {
          $section{'exprlist'}=$1;
          $section{'exprlist_line'} = $i;
        } elsif ($c[$i] =~ /^log\s+(\S+)/) {
          $section{'log'}=$1;
          $section{'log_line'} = $i;
        }
        $i++;
      }

      # All empty lines after the section
      # are counted to the section
      while (($i+1 < scalar(@c)) && (unify($c[$i+1]) eq "")) {
        $i++;
        $c[$i] = unify($c[$i]);
      }
      $section{'end_line'} = $i;

      push(@config, \%section);


    } elsif ($c[$i] =~ /^(rew|rewrite)\s+([-_.a-zA-Z0-9]+)\s+((within|outside)\s+([-_.a-zA-Z0-9]+)\s+)?\{\s*$/) {

      ###### Rewrite group

      print "<B>rewrite token found ($i)</B><BR>\n" if $_DEBUG;
      my %section;
	 $section{'counter'}=$counter++;
         $section{'sectype'}='rewrite';
         $section{'secname'}=$2;
         $section{'line'}=$i;
         $section{'tstype'} = $4;
         $section{'timespace'} = $5;

      my @members=();
      $c[$i] = unify($c[++$i]);
      while(($i < scalar(@c)) && ($c[$i] !~ /^\s*\}/)) {
        $c[$i] = unify($c[$i]);

        if ($c[$i] =~ /^s\@(\S+)\@(\S+)\@(i?)(r?)(R?)/) {
          my %st=();
             $st{'stype'}='rew';
             $st{'line'}=$i;
             $st{'from'}=$1;
             $st{'to'}=$2;
             $st{'flag_i'} = $3 ? 1 : 0;
             $st{'flag_r'} = $4 ? 1 : 0;
             $st{'flag_R'} = $5 ? 1 : 0;
          push(@members, \%st);  
        }

        $i++;
      }
      $section{'members'}=\@members;

      # All empty lines after the section
      # are counted to the section
      while (($i+1 < scalar(@c)) && (unify($c[$i+1]) eq "")) {
        $i++;
        $c[$i] = unify($c[$i]);
      }
      $section{'end_line'} = $i;


      push(@config, \%section);


    } elsif ($c[$i] =~ /^acl\s+\{\s*$/) {

      ###### ACL

      print "<B>acl token found ($i)</B><BR>\n" if $_DEBUG;
      my %section;
	 $section{'counter'}=$counter++;
         $section{'sectype'}='acl';
         $section{'secname'}=$2;
         $section{'line'}=$i;

      my @members=();
      $c[$i] = unify($c[++$i]);
      while(($i < scalar(@c)) && ($c[$i] !~ /^\s*\}/)) {
        if ($c[$i] =~ /\s*([-_.a-zA-Z0-9]+)\s+((within|outside)\s+([-_.a-zA-Z0-9]+)\s+)?\{/ ) {
            my %st;
               $st{'stype'} = 'acl_item';
               $st{'line'} = $i;
               $st{'source'} = $1;
               $st{'tstype'} = $3 ? $3 : 'none';
               $st{'timespace'} = $4;

            print "<B>acl_item found ($i)</B><BR><UL>\n",
                  "<LI>source: $st{'source'}</LI>\n",
                  "<LI>tstype: $st{'tstype'}</LI>\n",
                  "<LI>timespace: $st{'timespace'}</LI></UL>\n"
              if ($_DEBUG);

          $c[$i] = unify($c[++$i]);
          while (($i < scalar(@c)) && ($c[$i] !~ /^\s*\}/)) {
            if ($c[$i] =~ /^pass/) {
              my @pass=split(/\s+/, $c[$i]);
              shift @pass; # delete the first, it's always 'pass'...
              $st{'pass'} = \@pass;
              $st{'pass_line'} = $i;
              print "<I>Pass Statement: $c[$i]</I><BR>",
                    join('::', @pass), "-> ", scalar(@pass), "<BR>" if $_DEBUG;
            } elsif ($c[$i] =~ /^rewrite/) {
              my @rew = split(/\s+/, $c[$i]);
              shift @rew; # delete the first, it's always 'rewrite'...
              $st{'rewrite'} = \@rew;
              $st{'rewrite_line'} = $i;
              print "<I>Rewrite Statement: $c[$i]</I><BR>\n" if $_DEBUG;
            } elsif ($c[$i] =~ /^redirect\s+(.*)/) {
              my $tmp=$1;
              $tmp =~ /((301|302):)?(.*)/;
              $st{'redmode'} = $2;
              $st{'redurl'} = $3;
              $st{'redirect_line'} = $i;
              print "<I>Redirection Statement: $c[$i]</I><BR>\n" if $_DEBUG;
            } else {
              print "<I>Unknown Statement: $c[$i]</I><BR>\n" if $_DEBUG;
            }

            $c[$i] = unify($c[++$i]);
          } # end inner while

          # All empty lines after the section
          # are counted to the section
          while (($i+1 < scalar(@c)) && (unify($c[$i+1]) eq "")) {
            $i++;
            $c[$i] = unify($c[$i]);
          }
          $st{'end_line'} = $i;

          push(@members, \%st);
        } # end if start of acl_item
        $i++;
        $c[$i] = unify($c[$i]);
      } # end outer while
      $section{'members'} = \@members;

      # All empty lines after the section
      # are counted to the section
      while (($i+1 < scalar(@c)) && (unify($c[$i+1]) eq "")) {
        $i++;
        $c[$i] = unify($c[$i]);
      }
      $section{'end_line'} = $i;

      push(@config, \%section);
    }

  } # End main FOR loop

return wantarray ? @config : \@config;
}



sub find_section {
  my $config = shift;
  my $args   = shift;

  foreach my $c (@{$config}) {
    my $ok=1;
    for (keys %$args) {
      next if ($_ eq 'config');
      if ($c->{$_} !~ /^$args->{$_}$/) {
        $ok=0;
        last;
      }
    }

    return $c if ($ok);
  }

return undef;
}

sub find_sections_by_type {
  my $config = shift;
  my $type   = shift;
  my %sections = ();

  foreach my $c (@{$config}) {
    if( $c->{sectype} eq $type ) {
        $sections{$c->{secname}} = $c;
    }
  }

return \%sections;
}


# sgchown($file)
# Change user/group of file to squid
sub sgchown {
    system("chown -R squid /var/log/squidGuard/ /var/lib/squidGuard/");
}
  


# rebuild_db($file)
# Rebuild the dbfile $file with squidguard -C
sub rebuild_db {
  system("$bin -C '$_[0]' -c '$conffile");
}

# reload_squid
# Send Squid the HUP signal when db is rebuild
sub reload_squid {
    system("systemctl restart squid");
}

sub unify {
  my $string=$_[0];
  chomp $string;
  $string =~ s/\t+/ /g;
  $string =~ s/\s+/ /g;
  $string =~ s/^\s+//;

return $string;
}

sub execute
{
        my $this        = shift;
        my $command     = shift;
        my $ret         = '';
        if( $this->{PROXYSERVER_LOCAL} ) {
                $ret=`$command`;
        }
        else {
                $ret=`ssh proxy '$command'`;
        }
        return $ret;
}

if( $job eq "readJson" )
{
	jsonSetting();
}
elsif( $job eq "read" )
{
	readSetting();
}
elsif( $job eq "readRoom" )
{
	readRoomSetting($NAME);
}
elsif( $job eq "printAll" )
{
	printAll();
}
elsif( $job eq "writeUserSource" )
{
	my $config = parse_config();
	open(OUT,">/var/lib/squidGuard/db/$NAME");
	while(<>)
	{
		print OUT;
	}
	close(OUT);
	if( !grep(/$NAME/,@Sources) ) {
		my $allAllowed = {};
		my $reply      = {};
		my $acls   = find_section($config,{ sectype => 'acl' });
		foreach my $acl (@{$acls->{members}})
		{
			my $source =  $acl->{source};
			foreach my $pass ( @{$acl->{pass}} )
			{
				if( $pass =~ /!(.*)/ ) {
					$reply->{acls}->{$source}->{$1} = "false";
				} else {
					$reply->{acls}->{$source}->{$pass} = "true";
				}
			}
			if( defined $reply->{acls}->{$source}->{all} ) {
				$allAllowed->{$source} = "true";
			} else {
				$allAllowed->{$source} = "false";
			}
		}
		$reply->{source} = $NAME;
		$reply->{sourcetype} = 'userlist';
		apply($reply);
	}
}
elsif( $job eq "writeIpSource" )
{
	my $config = parse_config();
	open(OUT,">/var/lib/squidGuard/db/$NAME");
	while(<>)
	{
		print OUT;
	}
	close(OUT);
	if( !grep(/$NAME/,@Sources) ) {
		my $allAllowed = {};
		my $reply      = {};
		my $acls   = find_section($config,{ sectype => 'acl' });
		foreach my $acl (@{$acls->{members}})
		{
			my $source =  $acl->{source};
			foreach my $pass ( @{$acl->{pass}} )
			{
				if( $pass =~ /!(.*)/ ) {
					$reply->{acls}->{$source}->{$1} = "false";
				} else {
					$reply->{acls}->{$source}->{$pass} = "true";
				}
			}
			if( defined $reply->{acls}->{$source}->{all} ) {
				$allAllowed->{$source} = "true";
			} else {
				$allAllowed->{$source} = "false";
			}
		}
		$reply->{source} = $NAME;
		$reply->{sourcetype} = 'iplist';
		apply($reply);
	}
}
elsif( $job eq "writePositiveList" )
{
	my $config = parse_config();
	system("mkdir -p /var/lib/squidGuard/db/PL/$NAME/" ); 
	open(OUT,">/var/lib/squidGuard/db/PL/$NAME/domains");
	while(<>)
	{
		print OUT;
	}
	close(OUT);
	if( !grep(/$NAME/,@Destinations) ) {
		my $allAllowed = {};
		my $reply      = {};
		my $acls   = find_section($config,{ sectype => 'acl' });
		foreach my $acl (@{$acls->{members}})
		{
			my $source =  $acl->{source};
			foreach my $pass ( @{$acl->{pass}} )
			{
				if( $pass =~ /!(.*)/ ) {
					$reply->{acls}->{$source}->{$1} = "false";
				} else {
					$reply->{acls}->{$source}->{$pass} = "true";
				}
			}
			if( defined $reply->{acls}->{$source}->{all} ) {
				$allAllowed->{$source} = "true";
			} else {
				$allAllowed->{$source} = "false";
			}
		}
		$reply->{destination} = $NAME;
		apply($reply);
	}
	system("echo '' | /usr/sbin/squidGuard -C PL/$NAME/domains -c /etc/squid/squidguard.conf");
	sgchown();
}
elsif( $job eq "writeJson" )
{
	my $config = parse_config();
	my $acls   = find_section($config,{ sectype => 'acl' });
	my $allAllowed = {};
	my $reply      = {};
	my $var = do { local $/; <> };
	my $readAcls = decode_json($var);
        foreach my $acl (@{$acls->{members}})
        {
		my $source =  $acl->{source};
		foreach my $pass ( @{$acl->{pass}} )
		{
			if( $pass =~ /!(.*)/ ) {
				$reply->{acls}->{$source}->{$1} = "false";
			} else {
				$reply->{acls}->{$source}->{$pass} = "true";
			}
		}
		if( defined $reply->{acls}->{$source}->{all} ) {
			$allAllowed->{$source} = "true";
		} else {
			$allAllowed->{$source} = "false";
		}
        }
	foreach my $acl ( @$readAcls )
	{
		my $name = $acl->{name};
		foreach my $key ( keys %$acl )
		{
			next if( $key eq 'name' );
			$reply->{acls}->{$key}->{$name} = $acl->{$key} ? 'true' : 'false';
		}
	}
	apply($reply);
}
elsif( $job eq "write" )
{
	my $config = parse_config();
	my $acls   = find_section($config,{ sectype => 'acl' });
	my $allAllowed = {};
	my $reply      = {};
        foreach my $acl (@{$acls->{members}})
        {
		my $source =  $acl->{source};
		foreach my $pass ( @{$acl->{pass}} )
		{
			if( $pass =~ /!(.*)/ ) {
				$reply->{acls}->{$source}->{$1} = "false";
			} else {
				$reply->{acls}->{$source}->{$pass} = "true";
			}
		}
		if( defined $reply->{acls}->{$source}->{all} ) {
			$allAllowed->{$source} = "true";
		} else {
			$allAllowed->{$source} = "false";
		}
        }
	while(<>)
	{
		if( /(.*):(.*):(.*)$/ ) {
			if( $3 eq "delete" ) {
				 push(@listsToRemove, $2);
			} else {
				$reply->{acls}->{$1}->{$2} = $3;
			}
		}
	}
	apply($reply);
}
else
{
	print "\n\nUsage /usr/share/cranix/tools/squidGuard.pl read|printAll|write|writeJson|readJson|writePositiveList|writeIpSource|writeUserSource\n\n";
}

1;

