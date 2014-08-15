package NetPacket::ARP;
# ABSTRACT: Assemble and disassemble ARP (Address Resolution Protocol) packets.

use strict;
use vars;

BEGIN {
    require Exporter;

    our (@ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    @ISA = qw(Exporter NetPacket);

# Items to export into callers namespace by default
# (move infrequently used names to @EXPORT_OK below)

    @EXPORT = qw(
    );

# Other items we are prepared to export if requested

    @EXPORT_OK = qw(arp_strip
		    ARP_OPCODE_REQUEST ARP_OPCODE_REPLY RARP_OPCODE_REQUEST 
		    RARP_OPCODE_REPLY
		    ARPHRD_NETROM ARPHRD_ETHER ARPHRD_EETHER ARPHRD_AX25
		    ARPHRD_PRONET ARPHRD_CHAOS ARPHRD_IEEE802 ARPHRD_ARCNET
		    ARPHRD_APPLETLK ARPHRD_DLCI ARPHRD_ATM ARPHRD_METRICOM
		    ARPHRD_IEEE1394 ARPHRD_EUI64 ARPHRD_INFINIBAND
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    opcodes     => [qw(ARP_OPCODE_REQUEST ARP_OPCODE_REPLY RARP_OPCODE_REQUEST 
		       RARP_OPCODE_REPLY)],
    protos      => [qw(ARPHRD_NETROM ARPHRD_ETHER ARPHRD_AX25 ARPHRD_PRONET
		       ARPHRD_CHAOS ARPHRD_IEEE802 ARPHRD_ARCNET
		       ARPHRD_APPLETLK ARPHRD_DLCI ARPHRD_ATM ARPHRD_METRICOM
		       ARPHRD_IEEE1394 ARPHRD_EUI64 ARPHRD_INFINIBAND)],
    strip       => [qw(arp_strip)],
    );
}

# 
# List of opcode values
#

use constant ARP_OPCODE_REQUEST  => 1;
use constant ARP_OPCODE_REPLY    => 2;
use constant RARP_OPCODE_REQUEST => 3;
use constant RARP_OPCODE_REPLY   => 4;

#
# List of hardware identifiers
#

use constant ARPHRD_NETROM	=> 0;
use constant ARPHRD_ETHER	=> 1;
use constant ARPHRD_EETHER	=> 2;
use constant ARPHRD_AX25	=> 3;
use constant ARPHRD_PRONET	=> 4;
use constant ARPHRD_CHAOS	=> 5;
use constant ARPHRD_IEEE802	=> 6;
use constant ARPHRD_ARCNET	=> 7;
use constant ARPHRD_APPLETLK	=> 8;
use constant ARPHRD_DLCI	=> 15;
use constant ARPHRD_ATM		=> 19;
use constant ARPHRD_METRICOM	=> 23;
use constant ARPHRD_IEEE1394	=> 24;
use constant ARPHRD_EUI64	=> 27;
use constant ARPHRD_INFINIBAND	=> 32;

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

    # Decode ARP packet

    if (defined($pkt)) {
	($self->{htype}, $self->{proto}, $self->{hlen}, $self->{plen},
	 $self->{opcode}) = unpack('nnCCn', $pkt);

        my $fmt = sprintf('@8a%da%da%da%d', $self->{hlen}, $self->{plen},
			  $self->{hlen}, $self->{plen});

	($self->{sha}, $self->{spa}, $self->{tha}, $self->{tpa}) = 
	     unpack($fmt, $pkt);

	$self->{data} = undef;
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}


#
# Strip header from packet and return the data contained in it.  ARP
# packets contain no encapsulated data.
#

undef &arp_strip;
*arp_strip = \&strip;

sub strip {
    return undef;
}

#
# Construct a packet
#

my @required = qw(htype proto opcode sha spa tha tpa);

sub new {
    my $class = shift;
    my (%args) = @_;
    my $self;

    for my $arg (@required) {
	die "argument $arg not specified" unless (exists $args{$arg});
    }

    warn "arguments 'hlen' and 'plen' are ignored." if (exists $args{hlen} || exists $args{plen});

    die "arguments 'spa' and 'tpa' are inconsistent." if (length($args{spa}) != length($args{tpa}));
    die "arguments 'sha' and 'tha' are inconsistent." if (length($args{sha}) != length($args{tha}));

    $self = {};

    bless $self, $class;

    $self->{htype} = $args{htype};
    $self->{proto} = $args{proto};
    $self->{opcode} = $args{opcode};
    $self->{hlen} = length($args{sha});
    $self->{plen} = length($args{spa});
    $self->{sha} = $args{sha};
    $self->{tha} = $args{tha};
    $self->{spa} = $args{spa};
    $self->{tpa} = $args{tpa};

    $self->{_parent} = $self->{data} = undef;

    return $self;
}

sub length {
    my $self = shift;
    return (3 * 2 + 2 * 1 + 2 * $self->{hlen} + 2 * $self->{plen});
}

#
# Encode a packet
#

sub encode {
    my $self = shift;
    my $pkt;

    $pkt = pack('nnCCna*a*a*a*', $self->{htype}, $self->{proto}, $self->{hlen},
		$self->{plen}, $self->{opcode}, $self->{sha}, $self->{spa},
		$self->{tha}, $self->{tpa});

    return $pkt;
}

# Module return value

1;

__END__

=head1 SYNOPSIS

  use NetPacket::ARP;

  $tcp_obj = NetPacket::ARP->decode($raw_pkt);
  $tcp_pkt = NetPacket::ARP->encode(params...);   # Not implemented

=head1 DESCRIPTION

C<NetPacket::ARP> provides a set of routines for assembling and
disassembling packets using ARP (Address Resolution Protocol).  

=head2 Methods

=over

=item C<NetPacket::ARP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::ARP-E<gt>encode(param =E<gt> value)>

Return a ARP packet encoded with the instance data specified.  Not
implemented.

=back

=head2 Functions

=over

=item C<NetPacket::ARP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the TCP packet.
Since no payload data is encapulated in an ARP packet (only instance
data), this function returns undef.

=back

=head2 Instance data

The instance data for the C<NetPacket::ARP> object consists of
the following fields.

=over

=item htype

Hardware type.

=item proto

Protocol type.

=item hlen

Header length.

=item plen

Protocol length.

=item opcode

One of the following constants:

=over

=item * ARP_OPCODE_REQUEST

=item * ARP_OPCODE_REPLY

=item * RARP_OPCODE_REQUEST

=item * RARP_OPCODE_REPLY

=back

=item sha

Source hardware address.

=item spa

Source protocol address.

=item tha

Target hardware address.

=item tpa

Target protocol address.

=back

=head2 Exports

=over

=item default

none

=item exportable

none

=item tags

The following tags group together related exportable items.

=over

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

Print out arp requests on the local network.

  #!/usr/bin/perl -w

  use Net::PcapUtils;
  use NetPacket::Ethernet qw(:types);
  use NetPacket::ARP;

  sub process_pkt {
    my ($arg, $hdr, $pkt) = @_;

    my $eth_obj = NetPacket::Ethernet->decode($pkt);

    if ($eth_obj->{type} == ETH_TYPE_ARP) {
	my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
	print("source hw addr=$arp_obj->{sha}, " .
	      "dest hw addr=$arp_obj->{tha}\n");
    }
  }

Net::PcapUtils::loop(\&process_pkt);

=head1 TODO

=over

=item Implement encode() function

=item Does this work for protocols other than IP?  Need to read RFC.

=item Example is a bit silly

=back

=head1 COPYRIGHT

Copyright (c) 2001 Tim Potter.

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
