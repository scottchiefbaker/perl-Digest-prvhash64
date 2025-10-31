package Digest::prvhash64;
use strict;
use warnings;
our $VERSION = '0.1.1';

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(prvhash64 prvhash64_64m prvhash64_hex prvhash64_64m_hex);

require XSLoader;
XSLoader::load('Digest::prvhash64', $VERSION);

sub prvhash64_hex {
	my ($msg, $hash_len, $seed) = @_;
	$seed //= 0;

	my $bin = prvhash64($msg, $hash_len, $seed);
	my $ret = unpack('H*', $bin);

	return $ret;
}

sub prvhash64_64m_hex {
	my ($msg, $seed) = @_;
	$seed //= 0;

	my $v   = prvhash64_64m($msg, $seed);
	my $ret = sprintf('%016x', $v);

	return $ret;
}

1;
