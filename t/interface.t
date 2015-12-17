#!perl

use strict;
use warnings;

use FindBin;

use lib "$FindBin::Bin/../lib";

use Crypt::DRBG::Hash;
use Crypt::DRBG::HMAC;
use IO::Handle;
use Test::More;

my @classes = map { "Crypt::DRBG::$_" } qw/HMAC Hash/;

foreach my $class (@classes) {
	subtest "Class $class" => sub {
		subtest 'Instantiating objects' => sub {
			my $obj = $class->new(auto => 1);
			isa_ok($obj, $class, 'auto => 1 object');
			isa_ok($obj, 'Crypt::DRBG', 'auto => 1 object');

			$obj = $class->new(seed => 'my very secret seed');
			isa_ok($obj, $class, 'manual seed object');
			isa_ok($obj, 'Crypt::DRBG', 'manual seed object');
		};
	};
}

# The spec for HMAC and Hash requires that the seed, nonce, and personalization
# string just be concatenated.  This makes it convenient to test the interface
# parameters.
subtest 'Instantiation and generation' => sub {
	test_instantiation({seed => 'abc', nonce => 'def'}, 'seed/nonce');
	test_instantiation({
			seed => sub { 'abc' },
			nonce => sub { 'def' },
		},
		'seed/nonce as coderefs'
	);
	test_instantiation({
			seed => sub { 'ab' },
			nonce => sub { 'cd' },
			personalize => sub { 'ef' },
		},
		'seed/nonce/personalize as coderefs'
	);
	test_instantiation({seed => 'abcdef'}, 'seed');
	test_instantiation({seed => sub { 'abcdef' }}, 'seed as coderef');
};

subtest 'Fork safety' => sub {
	my $state = 0;
	my @tests = (
		{
			params => {seed => sub { $$ }, fork_safe => 1},
			desc => 'reseeds when fork safe',
		},
		{
			params => {auto => 1},
			desc => 'fork safe by default'
		},
		{
			params => {seed => sub { die if ++$state > 2; $$ }, fork_safe => 1},
			desc => 'does not keep reseeding',
		},
	);
	foreach my $test (@tests) {
		subtest $test->{desc} => sub {
			my %kids;
			my $obj = Crypt::DRBG::HMAC->new(%{$test->{params}});
			foreach my $kid (1..2) {
				pipe my $rfh, my $wfh;
				my $pid = fork;
				die 'No fork?' unless defined $pid;
				if ($pid > 0) {
					close($wfh);
					my @data = $rfh->getlines;
					chomp @data;
					$kids{$kid} = {
						data => join('', @data),
						pid => $pid,
					};
					waitpid($pid, 0);
				}
				else {
					close($rfh);
					for (1..2) {
						$wfh->print(unpack('H*', $obj->generate(10)), "\n");
					}
					exit;
				}
			}
			my $mine = $obj->generate(10) . $obj->generate(10);
			$mine = unpack('H*', $mine);
			isnt($mine, $kids{1}->{data}, "Data for kid 1 isn't mine");
			isnt($mine, $kids{2}->{data}, "Data for kid 2 isn't mine");
			isnt($kids{1}->{data}, $kids{2}->{data}, "kids are different");
		}
	}
};

subtest 'randitems' => sub {
	my $obj = Crypt::DRBG::HMAC->new(seed => 'my very secret seed');
	my @tests = (
		{
			count => 100,
			range => [0..9],
			desc => 'digits'
		},
		{
			count => 300,
			range => ['A'..'Z', 'a'..'z', '_'],
			desc =>'valid identifiers'
		},
		{
			count => 500,
			range => ['0'..'9', 'A'..'Z', 'a'..'z', '+', '/'],
			desc =>'base64'
		},
	);
	foreach my $test (@tests) {
		subtest "generate $test->{desc}" => sub {
			my @entries = $obj->randitems($test->{count}, $test->{range});
			is(scalar @entries, $test->{count}, 'correct number of items');
			my $buckets = {};
			$buckets->{$_}++ for @entries;
			my $total = 0;
			foreach my $item (@{$test->{range}}) {
				$total += $buckets->{$item};
				cmp_ok($buckets->{$item}, '>', 0, "At least one of $item");
			}
			is($total, scalar @entries, 'only expected characters exist');
		}
	}
};

subtest 'rand' => sub {
	my $obj = Crypt::DRBG::HMAC->new(seed => 'my very secret seed');

	my $max = 5;
	my $value = $obj->rand($max);
	is($value, 0x2bc5b19e / 2.0 / (2 ** 31) * $max, 'Value is as expected');

	my @tests = (
		{
			count => 100,
			arg => 5,
			desc => 'digits'
		},
	);
	foreach my $test (@tests) {
		subtest "generate $test->{desc}" => sub {
			my @entries = $obj->rand($test->{arg}, $test->{count});
			is(scalar @entries, $test->{count}, 'correct number of items');
			my $buckets = {};
			$buckets->{int($_)}++ for @entries;
			my $total = 0;
			foreach my $item (0..($test->{arg}-1)) {
				$total += $buckets->{$item};
				cmp_ok($buckets->{$item}, '>', 0, "At least one of $item");
			}
			is($total, scalar @entries, 'only expected numbers exist');
			is((grep { $_ >= $test->{arg} } @entries), 0, 'right range');
		}
	}
};

done_testing();

sub test_instantiation {
	my ($params, $desc) = @_;
	test_hmac_instantiation($params, $desc);
	test_hash_instantiation($params, $desc);
	return;
}

sub test_hash_instantiation {
	my ($params, $desc) = @_;
	my $expected = 'c7dfc3a61d94f45d0570';
	my $obj = Crypt::DRBG::Hash->new(%$params);
	my $hex = unpack 'H*', $obj->generate(10);
	is($hex, $expected, "Generates expected value for $desc");
	return;
}

sub test_hmac_instantiation {
	my ($params, $desc) = @_;
	my $expected = '10a912824b76baaec94b';
	my $obj = Crypt::DRBG::HMAC->new(%$params);
	my $hex = unpack 'H*', $obj->generate(10);
	is($hex, $expected, "Generates expected value for $desc");
	return;
}
