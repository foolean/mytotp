#!/usr/bin/perl -Tw

use strict;
use warnings;

use English qw(-no_match_vars);
use Test::More;
use POSIX qw(ceil);
use Readonly;

# We'll dynamically set lib
my $ROOTDIR = q{};
BEGIN {
    use Cwd 'abs_path';
    use File::Basename;

    $ROOTDIR = abs_path(dirname(__FILE__) . '/..');
    if ($ROOTDIR =~ m/^(\/[\/a-z0-9_.-]+)$/ig) {
        $ROOTDIR = $1;
    } else {
        printf "error: unable to untaint ROOTDIR\n";
        exit 1;
    }
}
use lib "$ROOTDIR/lib";

# Assemble the path to our test config
my $TEST_CONFIG = abs_path(dirname(__FILE__) . '/mytotp_test.conf');

use Authen::MyTOTP;
my $mytotp = Authen::MyTOTP->new( config => $TEST_CONFIG );

# Initialize variables
my $tests = 0;
my @entries;
my %entry;
my $result;

for my $bytes ( 1..64 ) {
    for my $count ( 1..25 ) {
        $tests += test_generate_secret($bytes * 8);
    }
}

done_testing( $tests );

sub test_generate_secret {
    my $bits = shift || return 0;
    my $tests = 0;

    my $secret = $mytotp->generate_secret($bits);
    my $secret_len = length $secret;
    my $wanted_len = ceil( ( $bits / 8 ) * 1.6 );
    ok( $secret_len == $wanted_len, "$bits bits generated $secret_len byte secret, wanted $wanted_len" );
    $tests++;

    ok( $secret =~ m/^[A-Z2-7]+$/smx, "'$secret' contains valid characters" );
    $tests++;

    return $tests;
}
