package NetPacket::Ethernet;
# ABSTRACT: Assemble and disassemble ethernet packets.

use strict;
use vars;
use NetPacket;
use Carp;

our (@ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);
BEGIN {
    require Exporter;
    @ISA = qw(Exporter NetPacket);

    @EXPORT = qw(from_eu48 to_eu48);

    my @eth_types = qw/ ETH_TYPE_IP        
                        ETH_TYPE_ARP       
                        ETH_TYPE_APPLETALK 
                        ETH_TYPE_RARP      
                        ETH_TYPE_SNMP      
                        ETH_TYPE_IPv6      
                        ETH_TYPE_PPP       
                        ETH_TYPE_802_1Q    
                        ETH_TYPE_IPX       
                        ETH_TYPE_PPPOED    
                        ETH_TYPE_PPPOES    /;

    @EXPORT_OK = ( 'eth_strip', 'ETH_HLEN', @eth_types ); 

    %EXPORT_TAGS = (
        ALL         => [@EXPORT, @EXPORT_OK],
        strip       => [qw(eth_strip)],
        types       => \@eth_types,
    );
}

#
# Partial list of ethernet protocol types from
# http://www.isi.edu/in-notes/iana/assignments/ethernet-numbers
#

use constant ETH_TYPE_IP        => 0x0800;
use constant ETH_TYPE_ARP       => 0x0806;
use constant ETH_TYPE_APPLETALK => 0x809b;
use constant ETH_TYPE_RARP      => 0x8035;
use constant ETH_TYPE_SNMP      => 0x814c;
use constant ETH_TYPE_IPv6      => 0x86dd;
use constant ETH_TYPE_PPP       => 0x880b;
use constant ETH_TYPE_802_1Q    => 0x8100;
use constant ETH_TYPE_IPX       => 0x8137;
use constant ETH_TYPE_PPPOED    => 0x8863;
use constant ETH_TYPE_PPPOES    => 0x8864;

use constant ETH_HLEN		=> 6;

#
# VLAN Tag field masks
#

use constant VLAN_MASK_PCP => 0xE000;
use constant VLAN_MASK_CFI => 0x1000;
use constant VLAN_MASK_VID => 0x0FFF;

sub to_eu48 {
    my $addr = shift;
    confess "not a eu48 address!" unless (length($addr) == 6);
    $addr = unpack('H12', $addr);
    $addr =~ s/[0-9a-f]{2,2}(?!$)/$&:/g;
    return $addr;
}

sub from_eu48 {
    my $addr = shift;
    # zero-pad single digits
    confess "not a eu48 address!"
	unless ($addr =~ m/^[0-9a-f]{12}$/ || $addr =~ m/^[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}$/);
    $addr =~ s/(?<=[:|^])[0-9a-f](?=[$|:])/0$&/g;
    $addr =~ s/://g;
    return pack('H12', $addr);
}

sub _validate_eu48 {
    my $addr = shift;
    if ($network_format) {
	confess "not a eu48 address!" unless (length($addr) == 6);
	return $addr;
    } else {
	confess "not a eu48 address!"
	    unless ($addr =~ m/^[0-9a-f]{12}$/ || $addr =~ m/^[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}$/);
	return $addr;
    }
}

sub _src_packed {
    my $self = shift;
    return ($network_format ? $self->{src_mac} : unpack('H12', $self->{src_mac}));
}

sub _dest_packed {
    my $self = shift;
    return ($network_format ? $self->{dest_mac} : unpack('H12', $self->{dest_mac}));
}


#
# Decode the packet
#

sub decode {
    my $class = shift;
    my($pkt, $parent) = @_;
    my $self = {};

    # Class fields

    $self->{_parent} = $parent;
    $self->{_frame} = $pkt;

    # Decode ethernet packet

    if (defined($pkt)) {

        my($sm, $dm, $tcid);

        ($dm, $sm, $self->{type}) = unpack('a6a6n', $pkt);

        # Check for 802.1Q VLAN tag and unpack to account for 4-byte offset
        if ($self->{type} == ETH_TYPE_802_1Q) {
            $self->{tpid} = ETH_TYPE_802_1Q;

            ( $tcid, $self->{type}, $self->{data} ) = unpack('x14nna*' , $pkt);

            # Break down VLAN tag TCI into: PCP, CFI, VID
            $self->{pcp} = $tcid & VLAN_MASK_PCP >> 13;
            $self->{cfi} = $tcid & VLAN_MASK_CFI >> 12;
            $self->{vid} = $tcid & VLAN_MASK_VID;
        }
        else {
            ( $self->{data} ) = unpack('x14a*' , $pkt);
        }

        $self->{src_mac} = ($network_format ? $sm : unpack('H12', $sm));
        $self->{dest_mac} = ($network_format ? $dm : unpack('H12', $dm));
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Strip header from packet and return the data contained in it
#

undef &eth_strip;        # Create eth_strip alias
*eth_strip = \&strip;

sub strip {
    my ($pkt) = @_;

    my $eth_obj = NetPacket::Ethernet->decode($pkt);
    return $eth_obj->{data};
}   

#
# Construct a packet
#

my @required = qw(type src_mac dest_mac data);

sub new {
    my $class = shift;
    my (%args) = @_;
    my $self;

    for my $arg (@required) {
	confess "argument $arg not specified" unless (exists $args{$arg});
    }

    $self = {};

    bless $self, $class;

    $self->{type} = $args{type};
    $self->{src_mac} = _validate_eu48($args{src_mac});
    $self->{dest_mac} = _validate_eu48($args{dest_mac});
    $self->{data} = $args{data};

    if (exists $args{vid} || exists $args{pcp} || exists $args{cfi}) {
	confess "vlan encoding requires vid, pcp, and cfi parameters"
		unless (exists $args{vid} && exists $args{pcp} && exists $args{c
i});

	$self->{pcp} = $args{pcp};
	$self->{cfi} = $args{cfi};
	$self->{vid} = $args{vid};
    }

    $self->{_parent} = undef;

    return $self;
}


#
# Encode a packet
#

sub encode {
    my $self = shift; 
    my ($frame, $vhdr);

    $vhdr = '';

    if (exists $self->{vid}) {
	my $tcid = $self->{vid} & VLAN_MASK_VID;
	$tcid |= (($self->{pcp} << 13) & VLAN_MASK_PCP);
	$tcid |= (($self->{cfi} << 12) & VLAN_MASK_CFI);

	$vhdr = pack('nn', ETH_TYPE_802_1Q, $tcid);
    }

    $frame = pack('a6a6a*na*', $self->_dest_packed(), $self->_src_packed(), $vhdr, $self->{type}, $self->{data});

    return $frame;
}

#
# Module initialisation
#

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 SYNOPSIS

  use NetPacket::Ethernet;

  $eth_obj = NetPacket::Ethernet->decode($raw_pkt);
  $eth_pkt = NetPacket::Ethernet->encode(params...);   # Not implemented
  $eth_data = NetPacket::Ethernet::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::Ethernet> provides a set of routines for assembling and
disassembling packets using the Ethernet protocol.  

=head2 Methods

=over

=item C<NetPacket::Ethernet-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::Ethernet-E<gt>encode(param =E<gt> value)>

Return an ethernet packet encoded with the instance data specified.
Not implemented.

=back

=head2 Functions

=over

=item C<NetPacket::Ethernet::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the ethernet
packet.  This data is suitable to be used as input for other
C<NetPacket::*> modules.

This function is equivalent to creating an object using the
C<decode()> constructor and returning the C<data> field of that
object.

=back

=head2 Instance data

The instance data for the C<NetPacket::Ethernet> object consists of
the following fields.

=over

=item src_mac

The source MAC address for the ethernet packet as a hex string.

=item dest_mac

The destination MAC address for the ethernet packet as a hex string.

=item type

The protocol type for the ethernet packet.

=item data

The payload for the ethernet packet.

=back

=head2 Exports

=over

=item default

none

=item exportable

ETH_TYPE_IP ETH_TYPE_ARP ETH_TYPE_APPLETALK ETH_TYPE_SNMP
ETH_TYPE_IPv6 ETH_TYPE_PPP 

=item tags

The following tags group together related exportable items.

=over

=item C<:types>

ETH_TYPE_IP ETH_TYPE_ARP ETH_TYPE_APPLETALK ETH_TYPE_SNMP
ETH_TYPE_IPv6 ETH_TYPE_PPP 

=item C<:strip>

Import the strip function C<eth_strip> which is an alias for
C<NetPacket::Ethernet::strip>

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

The following script dumps ethernet frames by mac address and protocol
to standard output.

  #!/usr/bin/perl -w

  use strict;
  use Net::PcapUtils;
  use NetPacket::Ethernet;

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

      my $eth_obj = NetPacket::Ethernet->decode($pkt);
      print("$eth_obj->{src_mac}:$eth_obj->{dest_mac} $eth_obj->{type}\n");
  }

  Net::PcapUtils::loop(\&process_pkt);

=head1 TODO

=over

=item Implement C<encode()> function

=back

=head1 COPYRIGHT

Copyright (c) 2001 Tim Potter and Stephanie Wehner.

Copyright (c) 1995,1996,1997,1998,1999 ANU and CSIRO on behalf of 
the participants in the CRC for Advanced Computational Systems
('ACSys').

This module is free software.  You can redistribute it and/or
modify it under the terms of the Artistic License 2.0.

This program is distributed in the hope that it will be useful,
but without any warranty; without even the implied warranty of
merchantability or fitness for a particular purpose.



=head1 AUTHOR

Tim Potter E<lt>tpot@samba.orgE<gt>

=cut

# any real autoloaded methods go after this line
