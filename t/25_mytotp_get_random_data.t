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

# Initialize variables
my $tests = 0;

for my $bytes ( 1..64 ) {
    for my $count ( 1..25 ) {
        $tests += test_get_random_data($bytes);
    }
}

done_testing( $tests );

sub test_get_random_data {
    my $bytes = shift || return 0;

    my $data = Authen::MyTOTP::_get_random_data($bytes);
    $data =~ s/(.)/sprintf("%02x",ord($1))/egsmx;
    my $data_len = ( length $data ) / 2;
    ok( $data_len == $bytes, "generated $data_len bytes of random data, wanted $bytes" );

    return 1;
}

