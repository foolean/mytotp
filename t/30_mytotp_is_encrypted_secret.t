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

$tests += test_is_encrypt_secret();

done_testing( $tests );

sub test_is_encrypt_secret {
    my $tests = 0;

    my $FH;
    open $FH, q{<}, 't/encrypt_secret.dat'
        or die "unable to open t/encrypt_pin.dat: $!";

    while ( my $line = <$FH> ) {
        chomp $line;
        my ( $secret, $pin, $esecret ) = split q{\|}, $line;

        if ( $pin =~ m/^([a-zA-Z0-9]+)$/smx ) {
            $pin = $1;
        }

        my $is_encrypted;

        $is_encrypted = Authen::MyTOTP::_is_encrypted_secret( $secret );
        ok( $is_encrypted == 0, "_is_encrypted_secret($secret) = 0" );
        $tests++;

        $is_encrypted = Authen::MyTOTP::_is_encrypted_secret( $esecret );
        ok( $is_encrypted == 1, "_is_encrypted_secret($esecret) = 1" );
        $tests++;
    }

    close $FH;
    return $tests;
}
