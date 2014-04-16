#!/usr/bin/perl
use strict;
use Net::Stomp;
use JSON;
my $stomp = Net::Stomp->new( { hostname => '192.168.10.99', port => '61613' } );
my $connection = $stomp->connect( { login => 'admin', passcode => 'password' } );
open DATA, "controller.cfg" or die "Can't open file: $!";
my $controllerid;
while (<DATA>) {
	chomp;
	($controllerid) = split /\|/;
}
close DATA;

die "OOPS" if !$controllerid;

while($connection)	{
	my $heartbeat = {controller=>$controllerid, ip=>"192.168.22.2", time=>time()};
	my $json = JSON->new->allow_nonref;
        my $jsonstr = $json->encode($heartbeat);
	$stomp->send({ destination => '/topic/heartbeats', body => $jsonstr });
	sleep(10);
}
print "ERROR";
$stomp->disconnect;
