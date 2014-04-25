#!/usr/bin/perl

use Net::Pcap;
use Data::Dumper;
use JSON;
use Net::Stomp;
use strict;

$| = 1;
my $err;
#Get the controller name from config file
open DATA, "controller.cfg" or die "Can't open file: $!";
my $controllerid;
while (<DATA>) {
        chomp;
        ($controllerid) = split /\|/;
}
close DATA;

die "OOPS" if !$controllerid;

#Initialise Stomp MQ
my $stomp = Net::Stomp->new( { hostname => '192.168.10.99', port => '61613' } );
$stomp->connect( { login => 'admin', passcode => 'password' } );
#Check monitor interface is active
my $dev = "mon0";
my $type = 'DLT_IEEE802_11';
unless (defined $dev) {
    $dev = Net::Pcap::lookupdev(\$err);
    if (defined $err) {
        die 'Unable to determine network device for monitoring - ', $err;
    }
}
#open the capture interface
my $capObj = Net::Pcap::open_live($dev, 2048, 0, 0, \$err);

unless (defined $capObj) {
    die 'Unable to create packet capture on device ', $dev, ' - ', $err;
}
my $pdump = Net::Pcap::dump_open($capObj, "cap.pcap"); #define pcap file for debug
#Define the loop for receiving packets
Net::Pcap::loop($capObj, -1, \&syn_packets, '') ||
        die 'Unable to perform packet capture';
Net::Pcap::close($capObj);

sub syn_packets {
        my ($user_data, $header, $packet) = @_;
        my $binpacket = asc2bin($packet); #Packet converted to binary
        my $parsed = parsepacket($binpacket); #Parse packet to hash
        Net::Pcap::dump($pdump, $header, $packet); # Dump packet to debug
        my $json = JSON->new->allow_nonref;#Define JSON object
        my $jsonstr = $json->encode($parsed); # Convert parsed hash to json
        $stomp->send({ destination => '/topic/packets', body => $jsonstr } );#Send JSON to message queue
}
sub parsepacket {
        my ($binpacket) = @_;
        my $packet;
        $packet->{CONTROLLER_ID} = $controllerid;
        #Begin splitting packet into their values
        $packet->{IEEE80211_RADIOTAP_REVISION} = oct(substr($binpacket, 0, 8));
        $packet->{IEEE80211_RADIOTAP_PAD} = oct("0b".substr($binpacket, 8, 8));
        $packet->{IEEE80211_RADIOTAP_LEN} = oct("0b".substr($binpacket, 16, 8));

        my $bitmap = substr($binpacket,32 , 32);
        $bitmap = oct("0b".$bitmap);
#use bitmap comparisons to see if the values are set
        $packet->{IEEE80211_RADIOTAP_PRESENT} = { #32
                'TSFT'=>($bitmap & 0x01000000) == 0x01000000,
                'FLAGS'=>($bitmap & 0x02000000) == 0x02000000,
                'RATE'=>($bitmap & 0x04000000) == 0x04000000,
                'CHANNEL'=>($bitmap & 0x08000000) == 0x08000000,
                'FHSS'=>($bitmap & 0x10000000) == 0x10000000,
                'DBM_ANT_SIGNAL'=>($bitmap & 0x20000000) == 0x20000000,
                'DBM_ANT_NOISE'=>($bitmap & 0x40000000) == 0x40000000,
                'LOCK_QUALITY'=>($bitmap & 0x80000000) == 0x80000000,
                'TX_ATTENUATION'=>($bitmap & 0x00010000) == 0x02000000,
                'DB_TX_ATTENUATION'=>($bitmap & 0x00020000) == 0x00020000,
                'DBM_TX_POWER'=>($bitmap & 0x00040000) == 0x00040000,
                'ANT'=>($bitmap & 0x00080000) == 0x00080000,
                'DB_ANT_SIGNAL'=>($bitmap & 0x00100000) == 0x00100000,
                'DB_ANT_NOISE'=>($bitmap & 0x00200000) == 0x00200000,
                'RX_FLAGS'=>($bitmap & 0x00400000) == 0x00400000,
                'MCS'=>($bitmap & 0x00000800) == 0x00008000,
                'A_MPDU'=>($bitmap & 0x00001000) == 0x00001000,
                'VHT_INFORMATION'=>($bitmap & 0x00002000) == 0x00002000,
                'RADIOTAP_NS_NEXT'=>($bitmap & 0x00000020) == 0x00000020,
                'VENDOR_NS_NEXT'=>($bitmap & 0x00000040) == 0x00000040,
                'EXT'=>($bitmap & 0x00000080) == 0x00000080
        };
        my $rtapref = 64;

        $rtapref+= 64 if($packet->{IEEE80211_RADIOTAP_PRESENT}{TSFT});
        $rtapref+= 8 if($packet->{IEEE80211_RADIOTAP_PRESENT}{FLAGS});
        if($packet->{IEEE80211_RADIOTAP_PRESENT}{RATE}) {
                $packet->{IEEE80211_RADIOTAP_RATE} = oct("0b".substr($binpacket,$rtapref , 8)) *500;
        }
        $rtapref+= 8; #Odd that the rate is still present even when = 0 in present field.
        if($packet->{IEEE80211_RADIOTAP_PRESENT}{CHANNEL})      {
                $packet->{IEEE80211_RADIOTAP_CHANNEL}{frequency} = oct("0b".substr($binpacket,$rtapref , 16));
                $rtapref+= 32;
        }
        $rtapref+= 16 if($packet->{IEEE80211_RADIOTAP_PRESENT}{FHSS});
        if($packet->{IEEE80211_RADIOTAP_PRESENT}{DBM_ANT_SIGNAL})      {
                $packet->{IEEE80211_RADIOTAP_SSI} = twoscomp(substr($binpacket,$rtapref , 8));
                print substr($binpacket,$rtapref , 8)."\n" if $packet->{IEEE80211_RADIOTAP_SSI} == 4;
        }

        my $packref = $packet->{IEEE80211_RADIOTAP_LEN} * 8;
        $packet->{IEEE80211_SUBTYPE} = oct("0b".substr($binpacket,$packref , 4));
        $packref +=4;
        $packet->{IEEE80211_TYPE} = oct("0b".substr($binpacket,$packref , 2));
        $packref +=2;
        $packet->{IEEE80211_VERSION} = oct("0b".substr($binpacket,$packref , 2));
        $packref+=2;
        $packet->{IEEE80211_RSVD} = substr($binpacket,$packref , 1);
        $packref++;
        $packet->{IEEE80211_PROTECTED} = substr($binpacket,$packref , 1);
        $packref++;
        $packet->{IEEE80211_MORE_DATA} = oct("0b".substr($binpacket,$packref , 1));
        $packref++;
        $packet->{IEEE80211_POWER_MGMT} = oct("0b".substr($binpacket,$packref , 1));
        $packref++;
        $packet->{IEEE80211_RETRY} = oct("0b".substr($binpacket,$packref , 1));
        $packref++;
        $packet->{IEEE80211_MORE_FRAG} = oct("0b".substr($binpacket,$packref , 1));
        $packref++;
        $packet->{IEEE80211_FROM_DS} = oct("0b".substr($binpacket,$packref , 1));
        $packref++;
$packet->{IEEE80211_TO_DS} = oct("0b".substr($binpacket,$packref , 1));
        $packref++;
        $packet->{IEEE80211_DURATION} = oct("0b".substr($binpacket,$packref , 16));
        $packref+=16;
        $packet->{IEEE80211_ADDR1} = substr($binpacket,$packref , 48);
        $packref+=48;
        $packet->{IEEE80211_ADDR2} = substr($binpacket,$packref , 48);
        $packref+=48;
        $packet->{IEEE80211_ADDR3} = substr($binpacket,$packref , 48);
        $packref+=48;
        $packet->{IEEE80211_SEQ} = oct("0b".substr($binpacket,$packref , 16));
        $packref+=16;
        $packet->{IEEE80211_ADDR4} = substr($binpacket,$packref ,48) if($packet->{IEEE80211_TO_DS} && $packet->{IEEE80211_FROM_DS});
        #convert MAC address fields to HEX
        my $address = "";
        my @hexmac = $packet->{IEEE80211_ADDR1} =~ m/(....)/g;
        foreach my $hex (@hexmac)       {
                $address.= sprintf('%X', oct("0b$hex"));
        }
        $packet->{IEEE80211_ADDR1_HEX} = $address;

        my $address = "";
        my @hexmac = $packet->{IEEE80211_ADDR2} =~ m/(....)/g;
        foreach my $hex (@hexmac)       {
                $address.= sprintf('%X', oct("0b$hex"));
        }
        $packet->{IEEE80211_ADDR2_HEX} = $address;

        my $address = "";
        my @hexmac = $packet->{IEEE80211_ADDR3} =~ m/(....)/g;
        foreach my $hex (@hexmac)       {
                $address.= sprintf('%X', oct("0b$hex"));
        }
        $packet->{IEEE80211_ADDR3_HEX} = $address;

        if($packet->{IEEE80211_TO_DS} && $packet->{IEEE80211_FROM_DS})  {
                my $address = "";
                my @hexmac = $packet->{IEEE80211_ADDR4} =~ m/(....)/g;
                foreach my $hex (@hexmac)       {
                        $address.= sprintf('%X', oct("0b$hex"));
                }
                $packet->{IEEE80211_ADDR4_HEX} = $address;
        }




        return $packet;
}
sub asc2bin { #Converts ascii to binary
        my ($str) = @_;
        my @bytes;
        for (split //, $str) {
              vec(my($byte), 0, 8) = ord;
              push @bytes, unpack "B8", $byte;
        }
        return wantarray ? @bytes : join "", @bytes;
}

sub twoscomp    { #runs twoscompliment to make ssi values negative
        my $num;
        my ($str, $bits) = @_;
        $bits ||=8;
        $bits--;
        for(my $i = 0; $i < $bits; $i++){$num += chop($str)*2**$i};
        $num *= -1 if ($str eq 1);
        return $num;

}
