#
# NetPacket::IGMP - Decode and encode IGMP (Internet Group Management
# Protocol) packets.

package NetPacket::IGMP;
# ABSTRACT: Assemble and disassemble IGMP (Internet Group Mangement Protocol) packets. 


use strict;
use vars;
use NetPacket qw(:ALL);
use NetPacket::IP;

our (@ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);
BEGIN {
    require Exporter;
    @ISA = qw(Exporter NetPacket);

# Items to export into callers namespace by default
# (move infrequently used names to @EXPORT_OK below)

    @EXPORT = qw(
    );

# Other items we are prepared to export if requested

    @EXPORT_OK = qw(igmp_strip
		    IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112
		    IGMP_VERSION_RFC2236 IGMP_VERSION_RFC3376
		    IGMP_MSG_HOST_MQUERY IGMP_MSG_HOST_MREPORT
		    IGMP_MSG_HOST_MQUERYv2 IGMP_MSG_HOST_MREPORTv1
		    IGMP_MSG_HOST_MREPORTv2 IGMP_MSG_HOST_LEAVE
		    IGMP_MSG_HOST_MREPORTv3
		    IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS
		    IGMP_IP_ALL_ROUTERS
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    strip       => [qw(igmp_strip)],
    versions    => [qw(IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112
		       IGMP_VERSION_RFC2236 IGMP_VERSION_RFC3376)],
    msgtypes    => [qw(IGMP_MSG_HOST_MQUERY IGMP_MSG_HOST_MREPORT
		       IGMP_MSG_HOST_MQUERYv2 IGMP_MSG_HOST_MREPORTv1
		       IGMP_MSG_HOST_MREPORTv2 IGMP_MSG_HOST_LEAVE
		       IGMP_MSG_HOST_MREPORTv3)],
    group_addrs => [qw(IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS
		      IGMP_IP_ALL_ROUTERS)]  
    );

}

#
# Version numbers
#

use constant IGMP_VERSION_RFC998  => 0;      # Version 0 of IGMP (obsolete)
use constant IGMP_VERSION_RFC1112 => 1;      # Version 1 of IGMP
use constant IGMP_VERSION_RFC2236 => 2;      # Version 2 of IGMP
use constant IGMP_VERSION_RFC3376 => 3;      # Version 3 of IGMP

#
# Message types
#

use constant IGMP_MSG_HOST_MQUERY  => 1;      # Host membership query
use constant IGMP_MSG_HOST_MREPORT => 2;      # Host membership report

use constant IGMP_MSG_HOST_MQUERYv2  => 0x11; # Host membership query
use constant IGMP_MSG_HOST_MREPORTv1 => 0x12; # Host membership report
use constant IGMP_MSG_HOST_MREPORTv2 => 0x16; # Host membership report
use constant IGMP_MSG_HOST_LEAVE     => 0x17; # Leave group

use constant IGMP_MSG_HOST_MREPORTv3 => 0x22; # Host membership report

#
# IGMP IP addresses
#

use constant IGMP_IP_NO_HOSTS    => '224.0.0.0';     # Not assigned to anyone
use constant IGMP_IP_ALL_HOSTS   => '224.0.0.1';     # All hosts on local net
use constant IGMP_IP_ALL_ROUTERS => '224.0.0.2';     # All routers on local net


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

    # Decode IGMP packet

    if (defined($pkt)) {
	($self->{type}, $self->{code}, $self->{cksum}, $self->{data}) =
		unpack('CCna4a*', $pkt);
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Strip header from packet and return the data contained in it.  IGMP 
# packets contain no encapsulated data.
#

undef &igmp_strip;
*igmp_strip = \&strip;

sub strip {
    return undef;
}

#
# Construct a packet
#

my @required = qw(type code data);

sub new {
    my $class = shift;
    my %args = @_;
    my $self;

    for my $arg (@required) {
	die "argument $arg not specified" unless (exists $args{$arg});
    }

    $self->{type} = $args{type};
    $self->{code} = $args{code};

    # would be nice to have variables to support formatting individual
    # message types.
    $self->{data} = $args{data};

    $self->{cksum} = $args{cksum} if (exists $args{cksum});

    $self->{_parent} = undef;

    bless $self, $class;
}

sub length {
    my $self = shift;
    return (4 + CORE::length($self->{data}));
}

#
# Compute checksum
#

sub checksum {
    my $self = shift;

    if (! exists $self->{cksum}) {
	my $packet = pack('CCna*', $self->{type}, $self->{code},
			  0, $self->{data});

	$self->{cksum} = htons(in_cksum($packet));
    }
    return $self->{cksum};
}

#
# Encode a packet
#

sub encode {
    my ($self, $ip) = @_;

    if (! exists $self->{cksum}) {
	die "need ip packet arg if checksum not already set" unless (defined $ip);
	$self->checksum();
    }

    my $packet = pack('CCna*', $self->{type}, $self->{code},
		      $self->{cksum}, $self->{data});
    return $packet;
}

# Module return value

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 SYNOPSIS

  use NetPacket::IGMP;

  $igmp_obj = NetPacket::IGMP->decode($raw_pkt);
  $igmp_pkt = NetPacket::IGMP->encode(params...);   # Not implemented
  $igmp_data = NetPacket::IGMP::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::IGMP> provides a set of routines for assembling and
disassembling packets using IGMP (Internet Group Mangement Protocol). 

=head2 Methods

=over

=item C<NetPacket::IGMP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::IGMP-E<gt>encode(param =E<gt> value)>

Return an IGMP packet encoded with the instance data specified.  Not
implemented.

=back

=head2 Functions

=over

=item C<NetPacket::IGMP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the IGMP
packet.  This function returns undef as there is no encapsulated data
in an IGMP packet.

=back

=head2 Instance data

The instance data for the C<NetPacket::IGMP> object consists of
the following fields.

=over

=item version

The IGMP version of this packet.

=item type

The message type for this packet.

=item len

The length (including length of header) in bytes for this packet.

=item subtype

The message subtype for this packet.

=item cksum

The checksum for this packet.

=item group_addr

The group address specified in this packet.

=item data

The encapsulated data (payload) for this packet.

=back

=head2 Exports

=over

=item default

none

=item exportable

IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112 IGMP_HOST_MQUERY
IGMP_HOST_MREPORT IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS
IGMP_IP_ALL_ROUTERS 

=item tags

The following tags group together related exportable items.

=over

=item C<:strip>

Import the strip function C<igmp_strip>.

=item C<:versions>

IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112

=item C<:msgtypes>

IGMP_HOST_MQUERY IGMP_HOST_MREPORT

=item C<:group_addrs>

IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS IGMP_IP_ALL_ROUTERS

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

The following script dumps UDP frames by IP address and UDP port
to standard output.

  #!/usr/bin/perl -w

  use strict;
  use Net::PcapUtils;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP;
  use NetPacket::IGMP;

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

      my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
      my $igmp_obj = NetPacket::IGMP->decode($ip_obj->{data});

      print("$ip_obj->{src_ip} -> $ip_obj->{dest_ip} ",
	    "$igmp_obj->{type}/$igmp_obj->{subtype} ",
	    "$igmp_obj->{group_addr}\n");
  }

  Net::PcapUtils::loop(\&process_pkt, FILTER => 'igmp');

=head1 TODO

=over

=item Implement encode() function

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
