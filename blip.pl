#!/usr/local/bin/perl -w
use strict;

=head1 PROGRAM

C<blip.pl> - Blocks and unblocks IPs using C<iptables>.

=head2 Usage Examples

Using the Unix iptables can be confusing, blip is a simple interface 
that un/blocks IPs and put them in a designated chain.

 ./blip.pl -block 114.80.97.88
 ./blip.pl -unblock 114.80.97.88

You can pass to it multiple IPs by separating them with commas.

List the blocked IPs:

 ./blip.pl -list

When you're tired of it all:

 ./blip.pl -wipe

=head2 Options

=head3 -verbose <level>

Turns on vebosity.

=head3 -bin <path-to-iptables>

Defaults to C</sbin/iptables> if it's not there, set it yourself.

=head3 -chain <chain>

Chain or target to add IPs to. Defaults to C<BLIP>.

=cut

use vars qw/$BLIP/;

use constant HELP => qq{blip.pl v1.0.1 - Block IP
 ./blip.pl -[un]block <ip-address> -verbose
 ./blip.pl -[wipe|list]
};

die HELP unless scalar @ARGV;

$BLIP = BlockIP->new(@ARGV);
$BLIP->commands;

exit (0);

package BlockIP;

use constant {
	IPTABLES => '/sbin/iptables',
	CHAIN    => 'BLIP'
};

=head1 NAME

C<BlockIP.pm> - Simple interface for C<iptables>.

=head1 SYNOPSIS

 $BLIP = BlockIP->new(@ARGV);
 $BLIP->commands;

=head1 DESCRIPTION

Blocks and unblocks IPs to a special chain called C<BLIP>.

=head2 Public Methods

=head3 new

Creates the object, subsequently, creates the C<CHAIN> if doesn't exist.

=cut

sub new {
	my $class = shift;
	my $self = {};

	for (my $i=0;$i<=$#_;$i++) {
		if (substr($_[$i],0,1) eq '-') {
			$self->{$_[$i]} = 1;
		} else {
			$self->{$_[$i-1]} = $_[$i];
		}
	}

	bless $self, $class;

	$self->_init;

	return $self;
}

=head3 commands (I<void>)

Accepts these command-line args:

 -verbose = 2 levels of outputs
 -list    = shows current table
 -wipe    = remove chain
 -block   = block this IP
 -unblock = unblock this IP

=cut

sub commands {
	my $self = shift;
	$self->{-data} or die "ABORT: Cannot find chain BLIP in iptables\n";

	if ($self->{-list}) {
		printf "Blocked IPs:\n%s\n", join "\n", $self->_get_ips;
	} elsif ($self->{-unblock}) {
		my @ips = split ',', $self->{-unblock};
		map { $self->unblock($_) } @ips;
	} elsif ($self->{-block}) {
		my @ips = split ',', $self->{-block};
		map { $self->block($_) } @ips;
	} elsif ($self->{-wipe}) {
		my $cmd = sprintf "%s -X %s",
			$self->{-bin}, $self->{-chain};

		$self->_printf(1,"Removing chain %s\n", $self->{-chain});
		map { $self->unblock($_) } $self->_get_ips;
		
		$self->_execute($cmd) and
			die "ERROR: Cannot wipe $cmd\n";
	}
}

=head3 block (I<ip>)

Blocks an IP if not already blacklisted.

=cut

sub block {
	my ($self,$ip) = (@_);

	if ($self->{-data} =~ /$self->{-block}/) {
		return print "ERROR: $ip already blocked\n";
	}
	my $cmd = sprintf "%s -I %s -s %s -j DROP",
		$self->{-bin}, $self->{-chain}, $ip;

	$self->_printf(1,"Blocking %s\n", $ip);

	$self->_execute($cmd) and
		die "ERROR: Cannot block $ip\n";
}

=head3 unblock (I<ip>)

Unblocks an IP in the C<chain>.

=cut

sub unblock {
	my ($self,$ip) = (@_);

	my $cmd = sprintf "%s -D %s -s %s -j DROP",
		$self->{-bin}, $self->{-chain}, $ip;

	$self->_printf(1,"Unblocking %s\n", $ip);

	$self->_execute($cmd) and
		die "ERROR: Cannot unblock $ip\n";
}

=head2 Private Methods

=head3 _init (I<void>)

Prepares C<iptables> to accept un/block of IPs.

=cut

sub _init {
	my $self = shift;

	$self->{-bin}     ||= IPTABLES;
	$self->{-chain}   ||= CHAIN;
	$self->{-verbose} ||= 0;

	my $cmd = sprintf "%s -L %s -n", $self->{-bin}, $self->{-chain};

	select STDOUT; $| = 1;
	local $/ = undef;

	my $info = $self->_execute($cmd);

	$info =~ /denied/i
		and die "ABORT: Need to be root to do this\n";

	if ($info =~ /no chain/i) {
		$self->_create_chain;
		$info = $self->_execute($cmd);
	}

	if ($info =~ /^target/m) {
		$self->{-data} = $info;
	}
}

sub _get_ips {
	my $self = shift;
	return () unless $self->{-data};

	my @list = ();
	while ($self->{-data} =~ m/--\s+(\d+\.\d+\.\d+\.\d+)/g) {
		push @list, $1;
	}
	return @list;
}

=head3 _create_chain (I<void>)

Creates a new C<chain> for these IPs.

=cut

sub _create_chain {
	my $self = shift;
	my $cmd = sprintf "%s -N %s", $self->{-bin}, $self->{-chain};

	$self->_printf(1, "$cmd\n");

	my $info = $self->_execute($cmd);
	$info and die "ABORT: $cmd failed ($info)\n";
}

=head3 _execute (I<command>,[I<reg-pattern>])

Execute command, if passed a regexp, it'll try to match it with the output
returns true/false otherwise, return entire output for parsing.

=cut

sub _execute {
	my ($self,$cmd,$re) = (@_);
	
	$self->_printf(2, "CMD: $cmd\n");

	open CMD, "$cmd 2>&1 |" or die "ABORT: Cannot execute $cmd\n";
	my $info = <CMD>;
	close CMD;

	$self->_printf(2, "%sOUTPUT%s\n%s\n%s\n\n",
		'-'x20,'-'x50,
		$info||'<empty>',
		'-'x76);

	$re and return $info =~ $re;

	return $info;
}

=head3 _printf (I<level>,I<format>,I<@array>)

Works just like C<printf> except has a built-in check for C<-verbose>.

=cut

sub _printf {
	my $self = shift;
	my $level = shift;

	return 0 if $self->{-verbose} < $level;

	return printf @_;
}

=head1 HISTORY

20120314 - v1.0 - Created. 

v1.0.1 - Remove C<README>. 
Link C<README.pod> to C<blip.pl>.
Change C<blip> to C<blip.pl>.
Adds C<-chain> option so user chan specify which C<chain/target> to use.

=head1 AUTHOR

This module by Paul Pham.

=head1 COPYRIGHT AND LICENSE

Copyright 2012 by Paul Pham

This program and library is free software;
you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

1;
