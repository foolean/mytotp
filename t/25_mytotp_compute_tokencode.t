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

$tests += test_compute_tokencode();

done_testing( $tests );

sub test_compute_tokencode {
    my $tests = 0;

    my $FH;
    open $FH, q{<}, 't/tokens.dat'
        or die "unable to open t/tokens.dat: $!";

    while ( my $line = <$FH> ) {
        chomp $line;
        my ( $secret, $tval, @codes ) = split q{\|}, $line;
    
        my $token = $mytotp->compute_tokencode( $secret, $tval );
        ok( $token eq $codes[1], "compute_tokencodes($secret, $tval) generated '$token', wanted '$codes[1]'");
        $tests++;
    }

    close $FH;
    return $tests;
}

