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
        printf "debug: unable to untaint ROOTDIR\n";
        exit 1;
    }
}
use lib "$ROOTDIR/lib";

# Assemble the path to our test config
my $TEST_CONFIG = abs_path(dirname(__FILE__) . '/mytotp_test.conf');

use Authen::MyTOTP;
my $mytotp = Authen::MyTOTP->new( config => $TEST_CONFIG );

# Initialize the test counter
my $tests = 0;

for my $bytes ( 1..64 ) {
    for my $count ( 1..25 ) {
        $tests += test_debug($bytes * 8);
    }
}

done_testing( $tests );

sub test_debug {
    my $bits = shift || return 0;
    my $tests = 0;

    my $secret = $mytotp->generate_secret($bits);
    my $arg1   = $mytotp->generate_secret(10);
    my $arg2   = $mytotp->generate_secret(10);

    my $srcmsg = sprintf 'testing debug message  %s', $secret;
    my $dstmsg = sprintf "debug: %s\n", $srcmsg;
    $Authen::MyTOTP::CONFIG{'debug'} = 1;
    stdout_is { Authen::MyTOTP::debug( $srcmsg ) } $dstmsg, 'debug on: ' . $dstmsg;
    $tests++;
    $Authen::MyTOTP::CONFIG{'debug'} = 0;
    stdout_is { Authen::MyTOTP::debug( $srcmsg ) } q{}, 'debug off: ' . $dstmsg;
    $tests++;

    $srcmsg = sprintf 'testing debug message %s (arg1=%%s,arg2=%%s)', $secret;
    $dstmsg = sprintf "debug: testing debug message %s (arg1=%s,arg2=%s)\n", $secret, $arg1, $arg2;
    $Authen::MyTOTP::CONFIG{'debug'} = 1;
    stdout_is { Authen::MyTOTP::debug( $srcmsg, $arg1, $arg2 ) } $dstmsg, 'debug on(): ' . $dstmsg;
    $tests++;
    $Authen::MyTOTP::CONFIG{'debug'} = 0;
    stdout_is { Authen::MyTOTP::debug( $srcmsg, $arg1, $arg2 ) } q{}, 'debug off(): ' . $dstmsg;
    $tests++;

    return $tests;
}

