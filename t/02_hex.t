use strict;
use warnings;
use Test::More;

use Digest::prvhash64 qw(
	prvhash64
	prvhash64_64m
	prvhash64_hex
	prvhash64_64m_hex
);

my @msgs  = (
	'',
	'a',
	'hello',
	"\x00\xff\x10\x80",
	"The quick brown fox jumps over the lazy dog",
);

my @seeds = (0, 1, 12345, 0xffffffff);
my @lens  = (8, 16, 24, 32); # bytes

# prvhash64_hex should equal unpack('H*', prvhash64(...))
for my $msg (@msgs) {
	for my $seed (@seeds) {
		for my $len (@lens) {
			my $bin = prvhash64($msg, $len, $seed);
			my $hex = prvhash64_hex($msg, $len, $seed);
			is($hex, unpack('H*', $bin), "prvhash64_hex matches binary hex for len=$len seed=$seed msg='" . substr($msg,0,16) . "'");
		}
	}
}

# prvhash64_64m_hex should equal sprintf('%016x', prvhash64_64m(...))
for my $msg (@msgs) {
	for my $seed (@seeds) {
		my $v   = prvhash64_64m($msg, $seed);
		my $hex = prvhash64_64m_hex($msg, $seed);
		is($hex, sprintf('%016x', $v), "prvhash64_64m_hex matches 64m hex seed=$seed msg='" . substr($msg,0,16) . "'");
		like($hex, qr/^[0-9a-f]{16}\z/, '64m hex is zero-padded lowercase 16 hex chars');
	}
}

done_testing();


