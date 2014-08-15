use strict;
use warnings;

use Test::More tests => 3;

use NetPacket::ARP qw(:opcodes :protos);
use NetPacket::Ethernet qw(:types ETH_HLEN from_eu48);
use NetPacket::IP;

use_network_format(1);

my $arp = NetPacket::ARP->new(
	htype => ARPHRD_ETHER,
	proto => ETH_TYPE_IP,
#	hlen => ETH_HLEN,
#	plen => 4,
	opcode => ARP_OPCODE_REQUEST,
	sha => from_eu48('52:54:0:b:80:9d'),
	spa => from_dotquad('192.168.122.91'),
	tha => from_eu48('0:0:0:0:0:0'),
	tpa => from_dotquad('192.168.122.55'),
);

my $eth = NetPacket::Ethernet->new(
	src_mac => from_eu48('52:54:0:b:80:9d'),
	dest_mac => from_eu48('ff:ff:ff:ff:ff:ff'),
	type => ETH_TYPE_ARP,
	data => $arp->encode(),
);

my $frame = binarize( <<'END_FRAME' );
ff ff ff ff ff ff 52 54 00 0b 80 9d 08 06 00 01
08 00 06 04 00 01 52 54 00 0b 80 9d c0 a8 7a 5b
00 00 00 00 00 00 c0 a8 7a 37
END_FRAME

sub binarize {
    my $string = shift;

    return join '' => map { chr hex } split ' ', $string;
}

my $eth2 = NetPacket::Ethernet->decode($frame);

# skip as part of the deep compare
delete $eth2->{_frame};

is_deeply($eth, $eth2, "ARP construction vs. decode");

is $eth2->{src_mac}, "\x52\x54\x00\x0b\x80\x9d", "binary MAC address";

my $arp2 = NetPacket::ARP->decode(substr($frame, 14));

# skip as part of the deep compare
delete $arp2->{_frame};

is_deeply($arp, $arp2, "2nd ARP construction test");
