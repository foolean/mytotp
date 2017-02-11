#!/usr/bin/perl -Tw

use strict;
use warnings;

use English qw(-no_match_vars);
use Test::More;
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

# Initialize variables
my $tests = 0;

# Make sure we can load the module
use_ok( 'Authen::MyTOTP' );
$tests++;

# Create our obejct
my $mytotp = Authen::MyTOTP->new( config => $TEST_CONFIG );

# ... did we get something defined?
ok( defined $mytotp, 'mytotp object defined' );
$tests++;

# ... is it our module?
isa_ok( $mytotp, 'Authen::MyTOTP' );
$tests++;

done_testing( $tests );
