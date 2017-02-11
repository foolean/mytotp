package Authen::MyTOTP;
#
# This file is part of Authen::MyTOTP.
#
# Authen::MyTOTP - My Time-Based One-Time Password
#
# Copyright 2017 Bennett Samowich <bennett@foolean.org>
#
# Authen::MyTOTP is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Authen::MyTOTP is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Authen::MyTOTP.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################
use strict;
use warnings 'all';

use Config::General qw(ParseConfig);
use Crypt::CBC;
use Data::Dumper;
use DBI;
use Digest::SHA qw(hmac_sha1_hex hmac_sha256_hex hmac_sha256_base64);
use English qw(-no_match_vars);
use Imager::QRCode;
use MIME::Base64;
use Net::Domain qw(hostfqdn);
use Net::LDAPS;
use POSIX qw(ceil);
use Readonly;
use Sys::Syslog;
use Time::Local;

our $PROGRAM = 'mytotp';
our $VERSION = '1.0.0';

our $DEBUG      = 0;
our $FREERADIUS = 0;
our $SYSLOG     = 0;
our $SYSLOG_ON  = 0;

# Defaults
Readonly our $DEFAULT_CONFIG_FILE  => '/etc/mytotp/mytotp.conf';
Readonly our $BITS_PER_BYTE        => 8;
Readonly our $DEFAULT_STEP_SIZE    => 30;
Readonly our $DEFAULT_SECRET_BITS  => 128;
Readonly our $SHA512_SALT_SIZE     => 16;
Readonly our $BLOCKSIZE            => 64;
Readonly our $ENCRYPTED_SECRET_TAG => '{MyTOTP}';

# Configuration
our %CONFIG;
our %TEMP;
our %DEFAULT_CONFIG = (
    debug          => 0,
    fail_lockout   => 0,
    freeradius     => 0,
    syslog         => 0,
    encrypt_secret => 0,
    enhanced_token => 0,
    db_type        => 'sqlite',
    db_name        => 'mytotp.db',
    db_path        => '/etc/mytotp/db',
    db_host        => 'localhost',
    db_user        => q{},
    db_pass        => q{},
    secret_bits    => $DEFAULT_SECRET_BITS,
    step_size      => $DEFAULT_STEP_SIZE,
    issuer         => hostfqdn(),
    lifetime       => 0,
);

# Class constructor
###############################################################################
sub new {
    my ( $class, %options ) = @_;

    # Process the incoming options that govern logging
    $FREERADIUS = $options{'freeradius'} || 0;

    # Create and bless an anonymous hash
    my $self = {};
    bless $self, $class;

    # Process the configuration file
    my $CONFIG_FILE = $DEFAULT_CONFIG_FILE;
    if ( exists $options{'config'} ) {
        $CONFIG_FILE = $options{'config'};
    }
    if ( !-e $CONFIG_FILE ) {
        fatal( 'unable to load configuration file "%s", file not found',
            $CONFIG_FILE );
        return;
    }
    %CONFIG = ParseConfig(
        -AutoTrue              => 1,
        -ConfigFile            => $CONFIG_FILE,
        -DefaultConfig         => \%DEFAULT_CONFIG,
        -LowerCaseNames        => 1,
        -MergeDuplicateOptions => 1,
    );
    if ( !%CONFIG ) {
        fatal( 'unable to parse configuration file "%s"', $CONFIG_FILE );
        return;
    }

    # Load the incoming options
    %CONFIG = (
        %CONFIG,
        ParseConfig(
            -AutoTrue              => 1,
            -ConfigHash            => \%options,
            -LowerCaseNames        => 1,
            -MergeDuplicateOptions => 1,
        )
    );

    # Normalize relative db_paths to /etc/mytotp/<db_path>
    if ( $CONFIG{'db_path'} !~ m/^\//smx ) {
        $CONFIG{'db_path'} = '/etc/mytotp/' . $CONFIG{'db_path'};
    }

    # Return the object
    return $self;
}

# Account manipulation routines
###############################################################################

# list_users
#   List accounts in the token database
sub list_users {
    my ( $self, @args ) = @_;

    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_list_users(@args);
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_list_users(@args);
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# get_user
#   Get a user's token account data
sub get_user {
    my ( $self, @args ) = @_;

    debug( 'getting account information for "%s"', $args[0] );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_get_user(@args);
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_get_user(@args);
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# del_user
#   Remove an account from the token database
# del_user
#   Remove an account from the token database
sub del_user {
    my ( $self, $username ) = @_;
    if ( !defined $username ) { return; }

    debug( 'deleting account "%s"', $username );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        my $query = 'DELETE FROM users WHERE username = ?';
        return $self->_db_run_query( $query, $username );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        my $filter = sprintf '(uid=%s)', $username;
        my $ldap_mesg = $self->_ldap_search($filter);
        if ( $ldap_mesg->code == 0 ) {
            my $entry = $ldap_mesg->entry(0);
            my $dn    = $entry->dn();

            $self->{'ldap'}->modify( $dn, delete => ['mytotpUsername'] );
            $self->{'ldap'}->modify( $dn, delete => ['mytotpStep'] );
            $self->{'ldap'}->modify( $dn, delete => ['mytotpSecret'] );
            $self->{'ldap'}->modify( $dn, delete => ['mytotpPin'] );
            $self->{'ldap'}->modify( $dn, delete => ['mytotpSkew'] );
            $self->{'ldap'}->modify( $dn, delete => ['mytotpExpires'] );
            $self->{'ldap'}->modify( $dn, delete => ['mytotpFailCount'] );
            $self->{'ldap'}->modify( $dn, delete => ['mytotpLastUsed'] );
            $self->{'ldap'}
              ->modify( $dn, delete => { 'objectClass' => 'mytotpToken' } );
        }
        return;
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# add_user
#   Add an account to the token database
sub add_user {
    my ( $self, $userent ) = @_;

    # Must have been given a hash reference
    if ( ref $userent ne 'HASH' ) {
        error('improper data for adding a new account');
        return;
    }

    # Must have a username
    if ( !exists $userent->{'username'} ) {
        error('no username specified');
        return;
    }

    # Must have a PIN
    if ( !exists $userent->{'pin'} ) {
        error('no pin specified');
        return;
    }

    # Set the default step size if we weren't passed one
    if ( !exists $userent->{'step'} ) {
        $userent->{'step'} = $CONFIG{'step_size'};
    }

    # Generate a secret if we weren't passed one
    if ( !exists $userent->{'secret'} ) {
        $userent->{'secret'} = $self->generate_secret();
    }

    # Default to no expiration
    if ( !exists $userent->{'expires'} ) {
        $userent->{'expires'} = 0;
    }

    # Process the lifetime value
    if ( !exists $userent->{'lifetime'} ) {
        $userent->{'lifetime'} = $CONFIG{'lifetime'};
    }
    if ( exists $userent->{'lifetime'} ) {
        my $expire = _compute_expiration( $userent->{'lifetime'} );
        if ( defined $expire ) {
            $userent->{'expires'} = $expire;
        }
    }

    # We're adding a new account so these should be zeroed
    $userent->{'skew'}       = 0;
    $userent->{'fail_count'} = 0;
    $userent->{'last_used'}  = 0;

    debug( 'adding account "%s"', $userent->{'username'} );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_add_user($userent);
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_add_user($userent);
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# lock_account
#   Lock a token account
sub lock_account {
    my ( $self, $username ) = @_;

    debug( 'locking account "%s"', $username );
    my $entry = $self->get_user($username);
    if ( !_is_account_locked( $entry->{'pin'} ) ) {
        $entry->{'pin'} = sprintf '!%s', $entry->{'pin'};
        $self->update_pin( $username, $entry->{'pin'} );
    }
    return;
}

# unlock_account
#   Unlock a token account
sub unlock_account {
    my ( $self, $username ) = @_;

    debug( 'unlocking account "%s"', $username );
    my $entry = $self->get_user($username);
    if ( _is_account_locked( $entry->{'pin'} ) ) {
        $entry->{'pin'} = substr $entry->{'pin'}, 1;
        $self->update_pin( $username, $entry->{'pin'} );
        $self->update_fail_count( $username, 0 );
    }
    return;
}

# update_expires
#   Update an account's expiration
sub update_expires {
    my ( $self, $username, $value ) = @_;

    debug( 'updating expiration for "%s"', $username );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_update_field( $username, 'expires', $value );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_update_field( $username, 'mytotpExpires', $value );
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# update_fail_count
#   Update an account's failed authentication counter
sub update_fail_count {
    my ( $self, $username, $value ) = @_;

    debug( 'updating failed login count for "%s" to "%s"', $username, $value );

    # Lock the account if we've passed the threshld
    if ( $CONFIG{'fail_lockout'} > 0 && $value > $CONFIG{'fail_lockout'} ) {
        $self->lock_account($username);
    }

    # Update the fail count
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_update_field( $username, 'fail_count', $value );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_update_field( $username, 'mytotpFailCount',
            $value );
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# update_last_used
#   Update the last successful authentication time slice
sub update_last_used {
    my ( $self, $username, $value ) = @_;

    debug( 'updating last login count for "%s" to "%s"', $username, $value );

    # Reset the fail count
    $self->update_fail_count( $username, 0 );

    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_update_field( $username, 'last_used', $value );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_update_field( $username, 'mytotpLastUsed', $value );
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# update_pin
#   Update an account's pin
sub update_pin {
    my ( $self, $username, $pin, $old_pin ) = @_;

    debug( 'updating the PIN for "%s"', $username );

    # Get the account's secret
    my $userent = $self->get_user($username);
    my $secret  = $userent->{'secret'};

    # Decrypt the secret if it's encrypted
    if ( _is_encrypted_secret($secret) == 1 ) {
        if ( !defined $old_pin ) {
            error(
'no current PIN, unable to decrypt secret for "%s", unable to update PIN',
                $username
            );
            return;
        }
        $secret = _decrypt_secret( $secret, $old_pin );
        if ( !defined $secret ) {
            error( 'unable to decrypt secret for "%s", unable to update PIN',
                $username );
            return;
        }
    }

    # Update the secret
    $self->update_secret( $username, $userent->{'secret'}, $pin );

    debug( 'updating PIN  for "%s"', $username );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_update_field( $username, 'pin', _encrypt_pin($pin) );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_update_field( $username, 'mytotpPin',
            _encrypt_pin($pin) );
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# update_secret
#   Update an account's shared secret
sub update_secret {
    my ( $self, $username, $secret, $pin ) = @_;

    debug( 'updating the shared secret for "%s"', $username );

    # Get the account's secret
    my $userent = $self->get_user($username);
    if ( $userent->{'pin'} ne crypt $pin, $userent->{'pin'} ) {
        error('unable to update the shared secret, invalid PIN');
        return;
    }

    # Encrypt or decrypt the secret as necessary
    if ( $CONFIG{'encrypt_secret'} ) {
        if ( !_is_encrypted_secret($secret) ) {
            $secret = _encrypt_secret( $secret, $pin );
        }
    }
    else {
        if ( _is_encrypted_secret($secret) ) {
            $secret = _decrypt_secret( $secret, $pin );
        }
    }

    debug( 'updating shared secret for "%s"', $username );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_update_field( $username, 'secret', $secret );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_update_field( $username, 'mytotpSecret', $secret );
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# update_step
#   Update an account's step value
sub update_step {
    my ( $self, $username, $value ) = @_;

    debug( 'updating step value for "%s" to "%s"', $username, $value );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_update_field( $username, 'step', $value );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_update_field( $username, 'mytotpStep', $value );
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# update_skew
#   Update the skew value for an account (may be removed in the future)
sub update_skew {
    my ( $self, $username, $value ) = @_;

    debug( 'updating skew value for "%s" to "%s"', $username, $value );
    if ( lc $CONFIG{'backend'} eq 'db' ) {
        return $self->_db_update_field( $username, 'skew', $value );
    }
    if ( lc $CONFIG{'backend'} eq 'ldap' ) {
        return $self->_ldap_update_field( $username, 'mytotpSkew', $value );
    }
    fatal( 'unsupported backend "%s"', $CONFIG{'backend'} );
    return;    # should never get here
}

# LDAP backend routines
###############################################################################

# _ldap_add_user
#   Internal method for the LDAP backend to add an account
#   to the token database
sub _ldap_add_user {
    my ( $self, $userent ) = @_;

    # Must have been given a hash reference
    if ( ref $userent ne 'HASH' ) {
        error('improper data for adding a new account');
        return;
    }

    # connect to the database if we're not already connected
    # (we need to do this here in order to use quote_identifier)
    if ( !$self->_ldap_is_active ) { $self->_ldap_connect(); }

    my $filter = sprintf '(uid=%s)', $userent->{'username'};
    my $ldap_mesg = $self->_ldap_search($filter);
    if ( $ldap_mesg->code == 0 ) {
        my $entry = $ldap_mesg->entry(0);
        my $dn    = $entry->dn();

        # Create the array of attributes for the new account
        my $ATTRS = [ objectClass => ['mytotpToken'] ];
        push @{$ATTRS}, mytotpUsername => $userent->{'username'};
        push @{$ATTRS}, mytotpStep     => $userent->{'step'};
        push @{$ATTRS}, mytotpSecret =>
          _encrypt_secret( $userent->{'secret'}, $userent->{'pin'} );
        push @{$ATTRS}, mytotpPin       => _encrypt_pin( $userent->{'pin'} );
        push @{$ATTRS}, mytotpSkew      => $userent->{'skew'};
        push @{$ATTRS}, mytotpExpires   => $userent->{'expires'};
        push @{$ATTRS}, mytotpFailCount => $userent->{'fail_count'};
        push @{$ATTRS}, mytotpLastUsed  => $userent->{'last_used'};

        my $result = $self->{'ldap'}->modify( $dn, add => { @{$ATTRS} } );
        if ( $result->code > 0 ) {
            error(
                'unable to create account for %s: %s',
                $userent->{'username'},
                $result->error
            );
            return 0;
        }
    }
    else {
        error(
            'user %s not found in ldap: %s',
            $userent->{'username'},
            $ldap_mesg->error
        );
        return 0;
    }
    return 1;
}

# _ldap_connect
#   Internal method for the LDAP backend to connect to the remote directory
sub _ldap_connect {
    my $self = shift;

    debug('connecting to LDAP');

    # Connect to the server
    $self->{'ldap'} = Net::LDAPS->new(
        $CONFIG{'ldap_uri'},
        verify  => $CONFIG{'ldap_verify'},
        cafile  => $CONFIG{'ldap_cacert'},
        timeout => $CONFIG{'ldap_timeout'},
        onerror => undef
    );

    # Determine if we were able to connect to the remote server
    if ( !defined $self->{'ldap'} ) {
        error( 'unable to connect to "%s"', $CONFIG{'ldap_uri'} );
        return 0;
    }

    # Bind to the server
    my $bind_result;
    if ( !defined $CONFIG{'ldap_binddn'} ) {
        $CONFIG{'ldap_anonymous'} = 1;    # We're connecting anonymously
        $bind_result = $self->{'ldap'}->bind();
    }
    else {
        $self->{'ldap_anonymous'} = 0;    # We're connecting with credentials
        $bind_result =
          $self->{'ldap'}
          ->bind( $CONFIG{'ldap_binddn'}, password => $CONFIG{'ldap_bindpw'} );
    }

    # Determine if we were able to bind
    if ( $bind_result->code != 0 ) {
        error( 'unable to bind to server: %s', $bind_result->error );
        return 0;
    }

    # Set our connected flag and return success
    $self->{'ldap_is_active'} = 1;
    return 1;
}

# _ldap_is_active
#   Internal method for the LDAP backend to return if the connection
#   to the remote directory is active
sub _ldap_is_active {
    my $self = shift;
    return $self->{'ldap_is_active'};
}

# _ldap_list_users
#   Internal method for the LDAP backend to list the accounts
#   in the token database
sub _ldap_list_users {
    my $self = shift;

    my $filter = '(&(objectClass=mytotpToken)(mytotpUsername=*))';
    debug( '_ldap_list_users(): filter = "%s"', $filter );
    my $ldap_mesg = $self->_ldap_search($filter);

    debug( 'got %s entries', $ldap_mesg->count );
    if ( $ldap_mesg->count > 0 ) {
        my $index = 0;
        while ( $index < $ldap_mesg->count ) {
            my $userent = $self->_ldap_entry( $ldap_mesg->entry($index) );
            printf "%s|%s|%s|%s|%s|%s|%s|%s\n",
              $userent->{'username'},
              $userent->{'step'},
              $userent->{'secret'},
              $userent->{'pin'},
              $userent->{'skew'},
              $userent->{'expires'},
              $userent->{'fail_count'},
              $userent->{'last_used'};
            $index++;
        }
    }
    return;
}

# _ldap_get_user
#   Internal method for the LDAP backend to get an account's data
sub _ldap_get_user {
    my ( $self, $username ) = @_;

    my $filter = sprintf '(&(objectClass=mytotpToken)(mytotpUsername=%s))',
      $username;

    my $ldap_mesg = $self->_ldap_search($filter);

    # If the search failed then set error message and return failure
    if ( $ldap_mesg->code == 0 ) {
        my $userent = $self->_ldap_entry( $ldap_mesg->entry(0) );

        return $userent;
    }
    return;
}

# _ldap_entry
#   Internal method for the LDAP backend to populate a hash reference
#   with an account's data.
sub _ldap_entry {
    my ( $self, $entry ) = @_;

    if ( !defined $entry ) { return; }

    my $userent;
    $userent->{'username'}   = _ldap_get_value( $entry, 'mytotpUsername' );
    $userent->{'step'}       = _ldap_get_value( $entry, 'mytotpStep' );
    $userent->{'secret'}     = _ldap_get_value( $entry, 'mytotpSecret' );
    $userent->{'pin'}        = _ldap_get_value( $entry, 'mytotpPin' );
    $userent->{'skew'}       = _ldap_get_value( $entry, 'mytotpSkew' );
    $userent->{'fail_count'} = _ldap_get_value( $entry, 'mytotpFailCount' );
    $userent->{'last_used'}  = _ldap_get_value( $entry, 'mytotpLastUsed' );
    $userent->{'expires'}    = _ldap_get_value( $entry, 'mytotpExpires' );

    return $userent;
}

# _ldap_search
#   Internal method for the LDAP backend to search the remote directory
sub _ldap_search {
    my ( $self, $filter ) = @_;

    # connect to the database if we're not already connected
    if ( !$self->_ldap_is_active ) { $self->_ldap_connect(); }

    # submit the search request to the remote server
    my $ldap_mesg = $self->{ldap}->search(
        base   => $CONFIG{'ldap_basedn'},
        filter => "$filter",
        attrs  => [
            'mytotpUsername', 'mytotpStep',
            'mytotpSecret',   'mytotpPin',
            'mytotpSkew',     'mytotpFailCount',
            'mytotpLastUsed', 'mytotpExpires',
        ],
        sizelimit => 0,
        debug     => 1,
    );

    if ( $ldap_mesg->code != 0 ) {
        error( 'search failed: %s', $ldap_mesg->error() );
    }

    return $ldap_mesg;
}

# _ldap_get_value
#   Internal method for the LDAP backend to return the first
#   value of an attribute or an empty string.
sub _ldap_get_value {
    my ( $entry, $attribute ) = @_;

    my $value = q{};
    if ( $entry->exists($attribute) ) {
        $value = ( $entry->get_value($attribute) )[0];
    }

    # Remove leading and trailing whitespace
    $value =~ s/^\s+|\s+$//smxg;

    return $value;
}

# _ldap_update_field
#   Internal method for the LDAP backend to update a field by name
sub _ldap_update_field {
    my ( $self, $username, $field, $value ) = @_;

    # connect to the database if we're not already connected
    # (we need to do this here in order to use quote_identifier)
    if ( !$self->_ldap_is_active ) { $self->_ldap_connect(); }

    my $filter = sprintf '(&(uid=%s)(mytotpUsername=%s))', $username, $username;
    my $ldap_mesg = $self->_ldap_search($filter);
    if ( $ldap_mesg->code == 0 ) {
        my $entry = $ldap_mesg->entry(0);
        my $dn    = $entry->dn();
        my $result =
          $self->{'ldap'}->modify( $dn, replace => { $field => $value } );
        if ( $result->code > 0 ) {
            error( 'unable to update %s for %s: %s',
                $field, $username, $result->error );
        }
    }
    return;
}

# Database backend routines
###############################################################################

# _db_list_users
#   Internal method for the DB backend to list accounts in the token database
sub _db_list_users {
    my $self = shift;

    my $query = 'SELECT * FROM users ORDER BY username';
    my $sth   = $self->_db_prepare($query);
    if ( defined $sth ) {
        $sth->execute();
        while ( my $userent = $sth->fetchrow_hashref() ) {
            printf "%s|%s|%s|%s|%s|%s|%s|%s\n",
              $userent->{'username'},
              $userent->{'step'},
              $userent->{'secret'},
              $userent->{'pin'},
              $userent->{'skew'},
              $userent->{'expires'},
              $userent->{'fail_count'},
              $userent->{'last_used'};
        }

        $sth->finish();
        $self->_db_disconnect();
    }
    return;
}

# _db_get_user
#   Internal method for the DB backend to et the token record for a specific
#   user and return it as a hash reference
sub _db_get_user {
    my ( $self, $username ) = @_;

    # connect to the database if we're not already connected
    if ( !$self->_db_is_active ) { $self->_db_connect(); }

    my $query = 'SELECT * FROM users WHERE username = ?';
    my $sth   = $self->_db_prepare($query);
    if ( defined $sth ) {
        $sth->execute($username);
        my $userent = $sth->fetchrow_hashref();
        $sth->finish();
        $self->_db_disconnect();    # Avoid SQLite locking issues

        return $userent;
    }
    return;
}

# _db_add_user
#   Internal method for the DB backend to add a user record
#   into the token database
sub _db_add_user {
    my ( $self, $userent ) = @_;

    # Must have been given a hash reference
    if ( ref $userent ne 'HASH' ) {
        error('improper data for adding a new account');
        return;
    }

    # Assemble the SQL query
    my $query = 'INSERT INTO users (';
    $query .= ' username, ';
    $query .= ' step, ';
    $query .= ' secret, ';
    $query .= ' pin, ';
    $query .= ' skew, ';
    $query .= ' expires, ';
    $query .= ' fail_count, ';
    $query .= ' last_used ';
    $query .= ' ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ? ) ';

    # ... run it
    return $self->_db_run_query(
        $query,
        $userent->{'username'},
        $userent->{'step'},
        _encrypt_secret( $userent->{'secret'}, $userent->{'pin'} ),
        _encrypt_pin( $userent->{'pin'} ),
        $userent->{'skew'},
        $userent->{'expires'},
        $userent->{'fail_count'},
        $userent->{'last_used'}
    );
}

# _db_update_field
#   Internal method to handle the updating of a
#   field in a user's token record.
sub _db_update_field {
    my ( $self, $username, $field, $value ) = @_;

    # connect to the database if we're not already connected
    # (we need to do this here in order to use quote_identifier)
    if ( !$self->_db_is_active ) { $self->_db_connect(); }

    my $field_safe = $self->{'dbh'}->quote_identifier($field);
    my $query      = sprintf 'UPDATE users SET %s = ? WHERE username = ?;',
      $field_safe;
    return $self->_db_run_query( $query, $value, $username );
}

# _db_run_query
#   Internal method to handle the actual running of
#   non-select database queries.
sub _db_run_query {
    my ( $self, $query, @data ) = @_;

    $self->_db_connect();    # Connect to the DB
    my $sth = $self->_db_prepare($query);    # Prepare the query
    if ( defined $sth ) {
        $sth->execute(@data);                # Execute with the data
        my $result = $self->_db_commit();    # Commit and capture the result
        $self->_db_disconnect();             # Disconnect from the DB
        return $result;
    }
    return;    # something went wrong, return undef
}

# _db_prepare
#   Internal method to handle the
#   DBI preparing of SQL statements.
sub _db_prepare {
    my ( $self, $sql ) = @_;

    # connect to the database if we're not already connected
    if ( !$self->_db_is_active ) { $self->_db_connect(); }

    my $sth = $self->{'dbh'}->prepare($sql);
    if ( !defined $sth ) {
        error( 'unable to prepare SQL: %s', $self->{'dbh'}->errstr );
    }
    return $sth;
}

# _db_commit
#   Internal method to handle the committing
#   of any uncommited transactions.
sub _db_commit {
    my $self   = shift;
    my $result = $self->{'dbh'}->commit();
    if ( !defined $result ) {
        error( 'unable to commit: %s', $self->{'dbh'}->errstr );
    }
    return $result;
}

# _db_connect
#   Internal method to handle connecting to a remote database
sub _db_connect {
    my $self = shift;

    # Just return 1 if we're already connected
    if ( $self->_db_is_active == 1 ) { return 1; }

    debug('connecting to the database');

    # Assemble the DSN
    my $dsn = q{};
    if ( lc $CONFIG{'db_type'} eq 'sqlite' ) {
        $dsn = sprintf 'dbi:SQLite:dbname=%s/%s',
          $CONFIG{'db_path'},
          $CONFIG{'db_name'};
    }
    if ( lc $CONFIG{'db_type'} eq 'mysql' ) {
        $dsn = sprintf 'dbi:MySQL:dbname=%s;host=%s;port=%s',
          $CONFIG{'db_name'},
          $CONFIG{'db_host'},
          $CONFIG{'db_port'};
    }
    if ( lc $CONFIG{'db_type'} eq 'postgres' ) {
        $dsn = sprintf 'dbi:PG:dbname=%s;host=%s;port=%s',
          $CONFIG{'db_name'},
          $CONFIG{'db_host'},
          $CONFIG{'db_port'};
    }

    # No DSN then "no soap batman!"
    if ( $dsn eq q{} ) { return; }

    # Connect to the database
    debug( 'connecting to database: "%s"', $dsn );
    $self->{'dbh'} = DBI->connect(
        $dsn,
        $CONFIG{'db_user'},
        $CONFIG{'db_pass'},
        {
            RaiseError         => 0,
            PrintError         => 0,
            ShowErrorStatement => 1,
            AutoCommit         => 0,
        },
    );

    if ( !defined $self->{'dbh'} ) {
        ## no critic(ProhibitPackageVars)
        fatal( 'unable to connect to "%s": %s', $dsn, $DBI::errstr );
        ## use critic
    }
    return 1;
}

# _db_is_active
#   Internal method to return the DBI active status
sub _db_is_active {
    my $self = shift;

    if ( exists( $self->{'dbh'} ) ) {
        return $self->{'dbh'}->{'Active'};
    }
    return 0;
}

# _disconect
#   Internal method to disconnect from a remote database
sub _db_disconnect {
    my $self = shift;

    if ( exists( $self->{'dbh'} ) ) {
        if ( $self->{'dbh'}->{'Active'} ) {

            my $result;
            $result = $self->{'dbh'}->rollback();
            if ( !defined $result ) {
                error( 'unable to rollback uncommitted changed: %s',
                    $self->{'dbh'}->errmsg );
            }
            debug('disconnecting from database');
            $self->{'dbh'}->disconnect();
        }
    }

    return;
}

# TOTP routines
###############################################################################

# validate_passcode
#   Validate a passcode using the data from the user's token record.
#   (this is the crux of the authentication processing)
sub validate_passcode {
    my ( $self, $username, $passcode ) = @_;

    my $userent = $self->get_user($username);
    if ( defined $userent ) {

        # Is the account locked?
        if ( _is_account_locked( $userent->{'pin'} ) ) {
            notice( 'AUTH_ACCOUNT_LOCKED: account %s is locked, rejecting',
                $username );
            return 0;
        }

        # Has the token expired?
        if ( $userent->{'expires'} > 0 && time > $userent->{'expires'} ) {
            notice( 'AUTH_EXPIRED_TOKEN: expired token for %s, rejecting',
                $username );
            return 0;
        }

        # Get the current time slice
        my $time_slice = int( time / $userent->{'step'} );

        # Has the token code already been used?
        if ( $time_slice <= $userent->{'last_used'} ) {
            notice(
'AUTH_TOKENCODE_REUSE: time slice "%s" already used for "%s", rejecting',
                $time_slice, $username
            );
            $self->update_fail_count( $username, $userent->{'fail_count'} + 1 );
            return 0;
        }

        # Parse the incoming passcode
        my $pin   = q{};
        my $token = q{};
        if ( $passcode =~ m/^(\w+)(\d{6})$/smx ) {
            $pin   = $1;
            $token = $2;
        }

        # Validate the PIN
        if ( $userent->{'pin'} ne crypt $pin, $userent->{'pin'} ) {
            notice( 'AUTH_INVALID_PIN: invalid PIN for "%s", rejecting',
                $username );
            $self->update_fail_count( $username, $userent->{'fail_count'} + 1 );
            return 0;
        }

        # Compute the previous, current, and next token codes
        my $secret = _decrypt_secret( $userent->{'secret'}, $pin );
        if ( !defined $secret ) {
            notice(
'AUTH_INVALID_SECRET: unable to decrypt secret for "%s", rejecting',
                $username
            );
            $self->update_fail_count( $username, $userent->{'fail_count'} + 1 );
            return 0;
        }
        my @token_codes = $self->compute_tokencodes( $secret, $time_slice );

        # Validate the TOKENCODE against the current code
        if ( $token eq $token_codes[1] ) {
            notice( 'AUTH_VALID_TOKENCODE: valid current TOKENCODE for "%s"',
                $username );
            $self->update_last_used( $username, $time_slice );
            return 1;
        }

        # Validate the TOKENCODE against the previous code
        if ( $token eq $token_codes[0] ) {
            notice( 'AUTH_VALID_TOKENCODE: valid previous TOKENCODE for "%s"',
                $username );
            $self->update_last_used( $username, $time_slice - 1 );
            return 1;
        }

        # Validate the TOKENCODE against the next code
        if ( $token eq $token_codes[2] ) {
            notice( 'AUTH_VALID_TOKENCODE: valid next TOKENCODE for "%s"',
                $username );
            $self->update_last_used( $username, $time_slice + 1 );
            return 1;
        }

        notice( 'AUTH_INVALID_TOKENCODE: invalid TOKENCODE for "%s", rejecting',
            $username );
        $self->update_fail_count( $username, $userent->{'fail_count'} + 1 );
        return 0;
    }
    else {
        notice( 'AUTH_USERNAME_NOT_FOUND: user "%s" not found, rejecting',
            $username );
    }
    return 0;
}

# generate_qr_image
#   Generate a QR code for the user to import into their TOTP app
sub generate_qr_image {
    my ( $self, $account, $secret, $step ) = @_;

    debug( 'generating QR for "%s"', $account );
    my $otp_url =
      sprintf 'otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%s',
      $CONFIG{'issuer'}, $account, $secret, $CONFIG{'issuer'}, $step;

    my $qrcode = Imager::QRCode->new(
        size          => 4,
        margin        => 2,
        version       => 0,
        level         => 'M',
        casesensitive => 1,
        lightcolor    => Imager::Color->new('#FFFFFF'),
        darkcolor     => Imager::Color->new('#000000'),
    );
    my $img = $qrcode->plot($otp_url);
    printf "Content-Type: image/gif\n\n";
    my $result = $img->write( fh => \*STDOUT, type => 'gif' );
    if ( !$result ) {
        fatal( 'unable to write QR image: %s', $img->errstr() );
    }
    exit 0;
}

# generate_qr_image_url
#   Generate a URL to Google's QR renderer that the user can use
#   to import into their TOTP app
sub generate_qr_image_url {
    my ( $self, $account, $secret, $step ) = @_;

    Readonly my $QR_SIZE => 200;
    my $otp_url =
      sprintf 'otpauth://totp/%s:%s%%3Fsecret%%3D%s%%26issuer=%s%%26period=%s',
      $CONFIG{'issuer'}, $account, $secret, $CONFIG{'issuer'}, $step;

    return
      sprintf 'https://%s?chs=%ix%i&cht=qr&chl=%ix%i&chld=M|0&cht=qr&chl=%s',
      'chart.googleapis.com/chart',
      $QR_SIZE, $QR_SIZE, $QR_SIZE, $QR_SIZE, $otp_url;

}

# generate_secret
#   generate a random base32 encoded secret.  The bit size
#   is normalized to a factor of 8.
sub generate_secret {
    my ( $self, $bits ) = @_;

    if ( !defined $bits || $bits !~ m/\d+/smx ) {
        $bits = $DEFAULT_SECRET_BITS;
    }

    # Round the bits up to the nearest byte
    $bits = ceil( $bits / $BITS_PER_BYTE ) * $BITS_PER_BYTE;

    # Generate and return the secret
    return _base32_encode( _get_random_data( $bits / $BITS_PER_BYTE ) );
}

# compute_tokencode
#   compute the current rfc6238 token code
sub compute_tokencode {
    my ( $self, $secret, $time_slice ) = @_;

    # call compute_tokencodes and simply return the current one
    my @token_codes = $self->compute_tokencodes( $secret, $time_slice );
    return $token_codes[1];
}

# compute_tokencodes
#   compute the previous, current, and next rfc6238 token codes.
sub compute_tokencodes {
    my ( $self, $secret, $time_slice ) = @_;

    my @tokens;
    my $key = _base32_decode($secret);

    my $max_time = $time_slice + 1;
    my $time     = $time_slice - 1;
    while ( $time <= $max_time ) {
        my $tval = sprintf '%016x', $time;
        my $data = pack 'H*', $tval;
        my $hmac = hmac_sha1_hex( $data, $key );

        # Compute a 6-digit OTP code based on rfc6238
        ## no critic(ProhibitMagicNumbers)
        my $offset = hex substr $hmac, -1;
        my $encrypted = hex( substr $hmac, $offset * 2, 8 ) & 0x7fffffff;
        my $token = $encrypted % 1_000_000;
        ## use critic

        push @tokens, sprintf '%06d', $token;

        $time += 1;
    }

    # Return the array of token codes
    return @tokens;
}

# get_random_data
#   get 'num_bytes' of random data
sub _get_random_data {
    my $num_bytes = shift;

    my $FH;      # file handle
    my $data;    # placeholder for the random data

    ## no critic(RequireBriefOpen)
    open $FH, q{<}, '/dev/urandom'
      or die "Unable to open /dev/urandom: $OS_ERROR\n";
    read $FH, $data, $num_bytes;
    close $FH or die "Unable to close /dev/urandom: $OS_ERROR\n";
    ## use critic

    return $data;
}

# _base32_encode
#   encode data using base32
#
#   borrowed from MIME::Base32
#   (slightly modified to satisfy perl critic)
sub _base32_encode {
    ## no critic(ProhibitMagicNumbers)
    # base32:
    #
    #  modified base64 algorithm with
    #  32 characters set:  A - Z 2 - 7 compliant with: RFC-3548
    #

    $_ = shift;
    my ( $l, $e );

    $_ = unpack 'B*', $_;
    s/(.....)/000$1/gsmx;
    $l = length;
    if ( $l & 7 ) {
        $e = substr $_, $l & ~7;
        $_ = substr $_, 0, $l & ~7;
        $_ .= "000$e" . '0' x ( 5 - length $e );
    }
    $_ = pack 'B*', $_;
    tr|\0-\37|A-Z2-7|;
    return $_;
    ## use critic
}

# _base32_decode
#   decode data that was encoded using base32
sub _base32_decode {
    my $val = shift;

    # turn into binary characters
    $val =~ tr|A-Z2-7|\0-\37|;

    # unpack into binary
    $val = unpack 'B*', $val;

    # cut off the 000 prefix
    $val =~ s/000(.....)/$1/gsmx;

    # trim off some characters if not 8 character aligned
    my $len = length $val;
    ## no critic(ProhibitMagicNumbers)
    if ( $len & 7 ) { $val = substr $val, 0, ( $len & ~7 ); }
    ## use critic

    # pack back up
    $val = pack 'B*', $val;
    return $val;
}

# Miscellaneous routines
###############################################################################

# _is_account_locked
#   Internal method to return if the account is locked or not
#   (accounts are locked by preceding the encrypted pin with a '!')
sub _is_account_locked {
    my $pin = shift || return 1;    # no pin at all means locked

    if ( ( substr $pin, 0, 1 ) eq q{!} ) {
        return 1;
    }
    return 0;
}

# _compute_expiration
#   Internal methad to convert a textual lifetime in the format of N[ymd]
#   to UNIX time. (e.g. 3y, 10m, 14d)
sub _compute_expiration {
    my $lifetime = shift;

    # Use the default lifetime if we weren't given one
    if ( !defined $lifetime ) {
        $lifetime = $CONFIG{'lifetime'};
    }

    # Return 0 if lifetime is 0 (no-expiration)
    if ( $lifetime eq '0' ) {
        return 0;
    }

    # Remove whitespace as a courtesy
    $lifetime =~ s/\s//gsmx;

    # Lifetime should be in a N[ymd] format (e.g. 3y, 6m, 90d)
    my $duration;
    my $ymd;
    if ( $lifetime =~ m/^([+-]*[\d]+)([mdy])$/smxi ) {
        $duration = $1;
        $ymd      = $2;
    }
    else {
        error( "invalid lifetime value '%s'\n", $lifetime );
        return;
    }

    ## no critic(ProhibitMagicNumbers)
    my $multiplier = 31_536_000;    # 1 year (the default)
    if ( lc $ymd eq 'm' ) {
        $multiplier = 2_592_000;    # 1 month
    }
    if ( lc $ymd eq 'd' ) {
        $multiplier = 86_400;       # 2 days
    }

    my @ltime = localtime( time + ( $duration * $multiplier ) );
    my $expire = timelocal( 0, 0, 0, $ltime[3], $ltime[4], $ltime[5] ) + 86_400;
    ## use critic

    return $expire;
}

# _is_encrypted_secret
#   Internal method to determine if a secret is encrypted
sub _is_encrypted_secret {
    my $secret = shift;

    if ( $secret =~ m/^\Q$ENCRYPTED_SECRET_TAG/smx ) {
        return 1;
    }
    return 0;
}

# _encrypt_secret
#   Internal method to encrypt a shared secret using the user's PIN
sub _encrypt_secret {
    my ( $data, $pin ) = @_;
    if ( !defined $pin ) { return; }
    if ( !$CONFIG{'encrypt_secret'} ) { return $data; }

    # Compute the IV using the PIN and the master key
    my $iv = substr hmac_sha256_hex( $pin, $CONFIG{'master_key'} ), 0,
      $BLOCKSIZE;

    # Create a Crypt::CBC object
    my $cipher_engine = Crypt::CBC->new(
        {
            'cipher'    => 'Crypt::Rijndael',
            'key'       => $pin,
            'iv'        => $iv,
            'header'    => 'none',
            'blocksize' => $BLOCKSIZE,
        }
    );

    # Generate the hmac and encrypted secret then
    # base64 encode the whole thing.
    $data = sprintf '%s:%s',
      hmac_sha256_base64( $data, $pin ),
      encode_base64( $cipher_engine->encrypt($data), q{} );
    $data = encode_base64( $data, q{} );
    return sprintf '%s%s', $ENCRYPTED_SECRET_TAG, $data;
}

# _decrypt_secret
#   Internal method to decrypt a shared secret using the user's PIN
sub _decrypt_secret {
    my ( $data, $pin ) = @_;
    if ( !defined $pin ) { return; }
    if ( !$CONFIG{'encrypt_secret'} ) { return $data; }

    if ( $data !~ m/^$ENCRYPTED_SECRET_TAG/smx ) { return $data; }

    # Compute the IV using the PIN and the master key
    my $iv = substr hmac_sha256_hex( $pin, $CONFIG{'master_key'} ), 0,
      $BLOCKSIZE;

    # Create a Crypt::CBC object
    my $cipher_engine = Crypt::CBC->new(
        {
            'cipher'    => 'Crypt::Rijndael',
            'key'       => $pin,
            'iv'        => $iv,
            'header'    => 'none',
            'blocksize' => $BLOCKSIZE,
        }
    );

    # strip the encrypted secret tag
    $data =~ s/^$ENCRYPTED_SECRET_TAG//smx;

    # base64 decode the whole thing then decrypt
    # and validate the encrypted secret.
    $data = decode_base64($data);
    if ( $data =~ m{^([[:alpha:]\d+/=]+):([[:alpha:]\d+/=]+)$}smx ) {

        # Decrypt the secret
        $data = $cipher_engine->decrypt( decode_base64($2) );

        # Validate the hmac
        if ( $1 eq hmac_sha256_base64( $data, $pin ) ) {
            return $data;
        }
    }
    return;
}

# _encrypt_pin
#   Internal method to handle the sha512crypt-ing of a PIN
sub _encrypt_pin {
    my $pin = shift || return;

    my $match_encrypted = q{\$}
      . '[[:digit:]]' . q{\$}
      . '[[:alpha:][:digit:].\/]+' . q{\$}
      . '[[:alpha:][:digit:].\/]+';

    # If the account is locked, assume it's already encrypted
    if ( _is_account_locked($pin) ) { return $pin; }

    # Encrypt the PIN if it isn't already
    if ( $pin !~ m{ ^$match_encrypted$ }smx ) {

        # Generate a 16-character salt
        my @chars = ( q{a} .. q{z}, q{A} .. q{Z}, q{0} .. q{9}, q{.}, q{/} );
        my $num   = scalar @chars;
        my $salt  = q{};
        my $i     = 0;
        while ( $i < $SHA512_SALT_SIZE ) {
            $salt .= $chars[ int rand $num ];
            $i++;
        }

        ## no critic(RequireInterpolationOfMetachars)
        my $epin = crypt $pin, sprintf '$6$%s$', $salt;
        ## use critic

        return $epin;
    }
    return $pin;
}

# Logging routines
###############################################################################

# notice
#   Print or log standard notification messages
sub notice {
    my ( $fmt, @args ) = @_;
    _log_message( undef, $fmt, @args );
    return;
}

# debug
#   Print or log debug messages
sub debug {
    my ( $fmt, @args ) = @_;

    if ( $CONFIG{'debug'} >= 1 ) {
        _log_message( 'debug', $fmt, @args );
    }
    return;
}

# error
#   Print or log error messages
sub error {
    my ( $fmt, @args ) = @_;
    _log_message( 'error', $fmt, @args );
    return;
}

# fatal
#   Print or log fatal error messages, and exit
sub fatal {
    my ( $fmt, @args ) = @_;
    _log_message( 'fatal', $fmt, @args );
    closelog();
    exit 1;
}

# _log_message
#   Internal method to handle the actual printing
#   and/or logging of messages to SYSLOG.
sub _log_message {
    my ( $type, $fmt, @args ) = @_;

    # Don't print debug messages if we're not debugging
    if ( defined $type ) {
        if ( !$CONFIG{'debug'} && $type eq 'debug' ) {
            return;
        }
    }

    # Open a connection to SYSLOG if not already open
    if ( $SYSLOG_ON == 0 ) {
        openlog( $PROGRAM, 'pid', 'user' );
        $SYSLOG_ON = 1;
    }

    # notice messages don't get a tag
    if ( defined $type && $type eq 'notice' ) {
        undef $type;
    }

    # Add the type tag
    if ( defined $type ) {
        $fmt = $type . ': ' . $fmt;
    }

    # Log to SYSLOG if running under FreeRADIUS
    # or if requested to send messages to SYSLOG.
    if ( $SYSLOG || $FREERADIUS ) {
        syslog( 'info', $fmt, @args );
    }

    # Print the message to STDOUT if not running under FreeRADIUS
    if ( !$FREERADIUS ) {
        printf $fmt . "\n", @args;
    }

    return;
}

# DESTROY
#   Class destructor - handle cleanup that wasn't explicitly called.
sub DESTROY {
    my $self = shift;

    if ( exists $CONFIG{'backend'} ) {
        if ( lc $CONFIG{'backend'} eq 'db' ) {
            $self->_db_disconnect();
        }
        if ( lc $CONFIG{'backend'} eq 'ldap' ) {
            debug('disconnecting from LDAP');
        }
    }
    closelog();
    return;
}

1;

__END__
