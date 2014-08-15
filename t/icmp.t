use strict;
use warnings;

use Test::More tests => 4;                      # last test to print

use NetPacket::Ethernet;
use NetPacket::IP qw(:protos :flags to_dotquad from_dotquad);
use NetPacket::ICMP qw(:types);

my $datagram = binarize( <<'END_DATAGRAM' );
00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 
00 54 00 00 40 00 40 01 3c a7 7f 00 00 01 7f 00 
00 01 08 00 d8 2f b6 6f 00 00 f8 11 c9 45 ba 05 
03 00 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 
16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 
26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 
36 37
END_DATAGRAM

my $eth = NetPacket::Ethernet->decode( $datagram );
my $ip = NetPacket::IP->decode( $eth->{data} );
my $icmp = NetPacket::ICMP->decode( $ip->{data} );

is $icmp->{cksum} => 55343, 'ICMP checksum';

# recompute the checksum
delete $icmp->{cksum};
$icmp->checksum;

is $icmp->{cksum} => 55343, 'recomputed ICMP checksum';

sub binarize {
    my $string = shift;

    return join '' => map { chr hex } split ' ', $string;
}

my $icmp2 = NetPacket::ICMP->new(
	type => ICMP_ECHO,
	code => 0,
	data => substr($datagram, 14 + 20 + 4),
);

# not dependent on IP header
$icmp2->checksum();

my $ip2 = NetPacket::IP->new(
	src_ip => '127.0.0.1',
	dest_ip => '127.0.0.1',
	proto => IP_PROTO_ICMP,
	ttl => 64,
	id => 0,
	flags => IP_FLAG_DONTFRAG,
	data => $icmp2->encode(),
);

$ip2->checksum();

# not included in deep compare
delete $icmp->{_frame};
delete $ip->{_frame};

is_deeply($icmp2, $icmp, "icmp decode/construct comparison");

is_deeply($ip2, $ip, "ip decode/construct comparison");

