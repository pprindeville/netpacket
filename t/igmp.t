use strict;
use warnings;

use Test::More tests => 4;                      # last test to print

use NetPacket::Ethernet;
use NetPacket::IP qw(:protos :flags to_dotquad from_dotquad);
use NetPacket::IGMP qw(:msgtypes);

my $datagram = binarize( <<'END_DATAGRAM' );
01 00 5e 00 00 01 d0 d0 fd 4c c1 73 08 00 46 00
00 20 2f 1a 00 00 01 02 54 12 c0 a8 01 02 e0 00
00 01 94 04 00 00 11 64 ee 9b 00 00 00 00
END_DATAGRAM

my $eth = NetPacket::Ethernet->decode( $datagram );
my $ip = NetPacket::IP->decode( $eth->{data} );
my $igmp = NetPacket::IGMP->decode( $ip->{data} );

is $igmp->{cksum} => 61083, 'IGMP checksum';

# recompute the checksum
delete $igmp->{cksum};
$igmp->checksum;

is $igmp->{cksum} => 61083, 'recomputed IGMP checksum';

sub binarize {
    my $string = shift;

    return join '' => map { chr hex } split ' ', $string;
}

my $igmp2 = NetPacket::IGMP->new(
	type => IGMP_MSG_HOST_MQUERYv2,
	code => 100,
	data => substr($datagram, 14 + 24 + 4),
);

# not dependent on IP header
$igmp2->checksum();

my $ip2 = NetPacket::IP->new(
	src_ip => '192.168.1.2',
	dest_ip => '224.0.0.1',
	proto => IP_PROTO_IGMP,
	ttl => 1,
	id => 12058,
	flags => 0,
	options => "\x94\x04\x00\x00",
	data => $igmp2->encode(),
);

$ip2->checksum();

# not included in deep compare
delete $igmp->{_frame};
delete $ip->{_frame};

is_deeply($igmp2, $igmp, "igmp decode/construct comparison");

is_deeply($ip2, $ip, "ip decode/construct comparison");

