#!perl

use strict;
use warnings;

use FindBin;

use lib "$FindBin::Bin/../lib";

use Crypt::DRBG::Hash;
use IO::Handle;
use Test::More;

my $obj = Crypt::DRBG::Hash->new(seed => '');
my $len = $obj->{seedlen};

my $all_zeros = "\x00" x $len;
my $all_ones = "\xff" x $len;
my $one = "\x00" x ($len-1) . "\x01";
compare($obj->_add($all_ones, $one), $all_zeros, "wraps around properly");
compare($obj->_add_int($all_ones, 1), $all_zeros, "int wraps around properly");

done_testing();

sub compare {
	my ($x, $y, $msg) = @_;
	is(length($x), $len, "length of x is correct");
	is(length($y), $len, "length is y correct");
	return is(unpack("H*", $x), unpack("H*", $y), $msg);
}
