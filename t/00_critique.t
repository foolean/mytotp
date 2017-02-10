#!/usr/bin/perl -w

use strict;
use warnings 'all';

use English qw(-no_match_vars);
use File::Spec;
use Test::More;

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

# Initialize the test counter
my $tests = 0;

# Make sure the source code is clean and sane (as sane can be)
# Note: Attempts to use $ROOTDIR failed so this test must be
#       called from the build root or via ./Build test.
eval { require Test::Perl::Critic; };
if ( $EVAL_ERROR ) {
    my $msg = 'Test::Perl::Critic required to criticise code';
    plan( skip_all => $msg );
}
Test::Perl::Critic->import( -profile => 't/perlcriticrc' );

my @FILES = qw(
    lib/MyTOTP.pm
    bin/mytotpadm
    bin/mytotp_qr
    sbin/mytotp_freeradius.pl
);

for my $FILE ( @FILES ) {
    critic_ok( $FILE, "critique of $FILE" );
    $tests++;
}

done_testing( $tests );

