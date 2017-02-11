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

$tests += test_base32();

done_testing( $tests );

sub test_base32 {
    my $tests = 0;

    my $FH;
    open $FH, q{<}, 't/base32.dat'
        or die "unable to open t/base32.dat: $!";

    while ( my $line = <$FH> ) {
        chomp $line;
        my ( $hex, $base32 ) = split q{\|}, $line;

        my $decoded = Authen::MyTOTP::_base32_decode( $base32 );
        $decoded =~ s/(.)/sprintf("%02x",ord($1))/egsmx;
        ok( $decoded eq $hex, "base32_decode($base32)");
        $tests++;
    }

    close $FH;
    return $tests;
}
