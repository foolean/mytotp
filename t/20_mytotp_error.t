#!/usr/bin/perl -Tw

use strict;
use warnings;

use English qw(-no_match_vars);
use Test::More;
use Test::Output;

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

use MyTOTP;
my $mytotp = MyTOTP->new( config => $TEST_CONFIG );

# Initialize the test counter
my $tests = 0;

for my $bytes ( 1..64 ) {
    for my $count ( 1..25 ) {
        $tests += test_error($bytes * 8);
    }
}

done_testing( $tests );

sub test_error {
    my $bits = shift || return 0;
    my $tests = 0;

    my $secret = $mytotp->generate_secret($bits);
    my $arg1   = $mytotp->generate_secret(10);
    my $arg2   = $mytotp->generate_secret(10);

    my $srcmsg = sprintf 'testing error message  %s', $secret;
    my $dstmsg = sprintf "error: %s\n", $srcmsg;
    stdout_is { MyTOTP::error( $srcmsg ) } $dstmsg, $dstmsg;
    $tests++;

    $srcmsg = sprintf 'testing error message %s (arg1=%%s,arg2=%%s)', $secret;
    $dstmsg = sprintf "error: testing error message %s (arg1=%s,arg2=%s)\n", $secret, $arg1, $arg2;
    stdout_is { MyTOTP::error( $srcmsg, $arg1, $arg2 ) } $dstmsg, $dstmsg;
    $tests++;

    return $tests;
}

