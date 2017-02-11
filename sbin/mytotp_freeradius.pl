#!/usr/bin/perl -w
#
# This file is part of MyTOTP.
#
# MyTOTP - My Time-Based One-Time Password
#
# Copyright 2017 Bennett Samowich <bennett@foolean.org>
#
# MyTOTP is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MyTOTP is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MyTOTP.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################
use strict;
use warnings 'all';

use English qw(-no_match_vars);
use File::Basename;
use Authen::MyTOTP;
use Readonly;

# Make sure that our hashes are filled from the main
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);

# Our program name and version
my $PROGRAM = basename(__FILE__);
our $VERSION = '1.0.0';

# Return value macros
Readonly my $RLM_MODULE_REJECT   => 0; # immediately reject the request
Readonly my $RLM_MODULE_FAIL     => 1; # module failed, don't reply
Readonly my $RLM_MODULE_OK       => 2; # module is OK, continue
Readonly my $RLM_MODULE_HANDLED  => 3; # module handled the request, so stop.
Readonly my $RLM_MODULE_INVALID  => 4; # module considers the request invalid.
Readonly my $RLM_MODULE_USERLOCK => 5; # reject the request (user is locked out)
Readonly my $RLM_MODULE_NOTFOUND => 6; # user not found
Readonly my $RLM_MODULE_NOOP     => 7; # module succeeded without doing anything
Readonly my $RLM_MODULE_UPDATED  => 8; # OK (pairs modified)
Readonly my $RLM_MODULE_NUMCODES => 9; # How many return codes there are

# Log type macros
Readonly my $RLM_LOG_DEBUG => 1;
Readonly my $RLM_LOG_AUTH  => 2;
Readonly my $RLM_LOG_INFO  => 3;
Readonly my $RLM_LOG_ERROR => 4;
Readonly my $RLM_LOG_PROXY => 5;
Readonly my $RLM_LOG_ACCT  => 6;

# Function to handle authorize
sub authorize {
    do_syslog('authorize()');
    return $RLM_MODULE_OK;
}

# Function to handle authenticate
sub authenticate {
    do_syslog('authenticate()');
    return mytotp_auth();
}

# Function to handle preacct
sub preacct {
    do_syslog('preacct()');
    return $RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
    do_syslog('accounting()');
    return $RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {
    do_syslog('checksimul()');
    return $RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
    do_syslog('pre_proxy()');
    return $RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
    do_syslog('post_proxy()');
    return $RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
    do_syslog('post_auth()');
    return $RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
    do_syslog('xlat()');
    return;
}

# Function to handle detach
sub detach {
    do_syslog('detach()');
    return;
}

# Log all of the values in the request
sub log_attributes {

    # For debugging use only!
    foreach my $key ( keys %RAD_REQUEST ) {
        do_syslog( 'RAD_REQUEST[%s] = "%s"', $key, $RAD_REQUEST{$key} );
    }

    # For debugging use only!
    foreach my $key ( keys %RAD_REPLY ) {
        do_syslog( 'RAD_REPLY[%s] = "%s"', $key, $RAD_REPLY{$key} );
    }

    # For debugging use only!
    foreach my $key ( keys %RAD_CHECK ) {
        do_syslog( 'RAD_CHECK[%s] = "%s"', $key, $RAD_CHECK{$key} );
    }
    return;
}

# Main MyTOTP authentication handler
sub mytotp_auth {

    my $MYTOTP = Authen::MyTOTP->new( freeradius => 1 );

    # For the moment, all logging is handled by MyTOTP
    if (
        $MYTOTP->validate_passcode(
            $RAD_REQUEST{'User-Name'},
            $RAD_REQUEST{'User-Password'}
        )
      )
    {
        return $RLM_MODULE_OK;
    }
    return $RLM_MODULE_REJECT;
}

# Helper routine to streamline logging
sub do_syslog {
    my ( $format, @args ) = @_;

    my $message = sprintf '%s: ', $PROGRAM;
    $message .= sprintf $format, @args;

    radiusd::radlog( $RLM_LOG_INFO, $message );
    return;
}

1;
