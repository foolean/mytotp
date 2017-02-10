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
my $mytotp = MyTOTP->new( config => $TEST_CONFIG );

# Initialize variables
my $tests = 0;

$tests += test_compute_tokencodes();

done_testing( $tests );

sub test_compute_tokencodes {
    my $tests = 0;

    my $FH;
    open $FH, q{<}, 't/tokens.dat'
        or die "unable to open t/tokens.dat: $!";

    while ( my $line = <$FH> ) {
        chomp $line;
        my ( $secret, $tval, @codes ) = split q{\|}, $line;
    
        my @tokens = $mytotp->compute_tokencodes( $secret, $tval );
        ok( $tokens[0] eq $codes[0], "compute_tokencodes($secret, $tval) generated (-1) '$tokens[0]', wanted '$codes[0]'");
        $tests++;
        ok( $tokens[1] eq $codes[1], "compute_tokencodes($secret, $tval) generated (0) '$tokens[1]', wanted '$codes[1]'");
        $tests++;
        ok( $tokens[2] eq $codes[2], "compute_tokencodes($secret, $tval) generated (+1) '$tokens[2]', wanted '$codes[2]'");
        $tests++;
    }

    close $FH;
    return $tests;
}

