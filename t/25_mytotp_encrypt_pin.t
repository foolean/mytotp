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

use MyTOTP;

# Initialize variables
my $tests = 0;

$tests += test_encrypt_pin();

done_testing( $tests );

sub test_encrypt_pin {
    my $tests = 0;

    my $FH;
    open $FH, q{<}, 't/encrypt_pin.dat'
        or die "unable to open t/encrypt_pin.dat: $!";

    while ( my $line = <$FH> ) {
        chomp $line;
        my ( $pin, $epin ) = split q{\|}, $line;

        my $encrypted = MyTOTP::_encrypt_pin( $epin );
        ok( $epin eq $encrypted, "encrypt_pin($epin) recognizes encrypted pin" );
        $tests++;

        $encrypted = MyTOTP::_encrypt_pin( $pin );
        my $enc = crypt $pin, $encrypted;
        ok( $enc eq $encrypted, "encrypt_pin($pin) = $encrypted" );
        $tests++;
    }

    close $FH;
    return $tests;
}
