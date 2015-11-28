#!perl

use strict;
use warnings;

use FindBin;

use lib "$FindBin::Bin/../lib";

use Crypt::DRBG::HMAC;
use IO::File;
use Time::HiRes;

use Test::More;

my %base_params = (
	seed => "\x00" x 111,
	nonce => "\x01" x 111,
	personalize => '',
);
my @tests = (
	{
		desc => '1024 bytes (1 chunk)',
		repeat => 1,
		count => 1024,
		timeout => 3,
	},
	{
		desc => '1024 bytes (16 chunks)',
		repeat => 16,
		count => 64,
		timeout => 3,
	},
	{
		desc => '1 MiB (16 chunks)',
		repeat => 16,
		count => 65536,
		timeout => 240,
	},
);
my %objs;
my @functions = (
	{
		func => \&urandom,
		name => 'urandom',
	},
	{
		func => sub { return hmac_drbg('a', $_[0], %base_params) },
		name => 'uncached HMAC',
	},
	{
		func => sub { return hmac_drbg('b', $_[0], auto => 1) },
		name => 'uncached HMAC (auto)',
	},
	{
		func => sub {
			return hmac_drbg('c', $_[0], %base_params, cache => 1024)
		},
		name => 'cached HMAC',
	},
	{
		func => sub {
			return hmac_drbg('d', $_[0], auto => 1, cache => 1024)
		},
		name => 'cached HMAC (auto)',
	},
	{
		func => sub {
			return hmac_drbg('e', $_[0], %base_params, cache => 65536)
		},
		name => 'cached HMAC (large)',
	},
);

foreach my $test (@tests) {
	subtest $test->{desc} => sub {
		plan tests => scalar @functions;
		foreach my $routine (@functions) {
			my $timeout = $test->{timeout};
			my $func = $routine->{func};
			my $t0 = [Time::HiRes::gettimeofday];
			foreach (1..100) {
				foreach (1..$test->{repeat}) {
					$func->($test->{count});
				}
			}
			my $t1 = [Time::HiRes::gettimeofday];
			my $secs = Time::HiRes::tv_interval($t0, $t1);
			cmp_ok($secs, '<', $timeout,
				"$routine->{name} completed in less than $timeout seconds");
			diag "$routine->{name} took $secs seconds";
		}
	};
}

done_testing();

sub urandom {
	my ($bytes) = @_;
	my $fh = IO::File->new('/dev/urandom', 'r');

	$fh->read(my $buf, $bytes);
	return $buf;
}

sub hmac_drbg {
	my ($cache_id, $bytes, %params) = @_;

	my $drbg = $objs{$cache_id} ||= Crypt::DRBG::HMAC->new(%params);
	return $drbg->generate($bytes);
}
