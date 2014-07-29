use strict;
use warnings;

use Test::More tests => 4;

use NetPacket::Ethernet qw/ :types from_eu48 to_eu48 /;

is ETH_TYPE_PPPOES() => 0x8864, 'imports';

is NetPacket::Ethernet::ETH_TYPE_IP() => 0x0800, 'with namespace';

my $addr = from_eu48('52:54:0:b:80:9d');

is $addr, "\x52\x54\x00\x0b\x80\x9d", "from_eu48 helper";

is to_eu48($addr), "52:54:00:0b:80:9d", "to_eu48 helper";

