use strict;
use warnings;

use Data::Dumper;
use Digest::SHA;
use File::Copy;
use File::Path qw( make_path rmtree );
use Module::Build;

our $VERSION = '1.0.0';

my $class = Module::Build->subclass( code => <<'EOF');
    sub ACTION_install {
        my $self = shift;

        # Call the parent install function
        $self->SUPER::ACTION_install;
    }

    sub ACTION_distclean {
        my $self = shift;
        use File::Basename;

        my $testdb = $self->base_dir() . '/t/db/mytotp_test.db';
        if ( -f $testdb ) {
            printf "Removing t/db/mytotp_test.db\n", $testdb;
            unlink $testdb;
        }

        # Call the parent distclean function
        $self->SUPER::ACTION_distclean;
    }

    sub ACTION_uninstall {
        my $self = shift;

        my $bin_files = $self->{'properties'}->{'bin_files'};
        foreach my $key ( keys %{$bin_files} ) {
            if ( -f $bin_files->{$key} ) {
                printf "Removing %s\n", $bin_files->{$key};
                unlink $bin_files->{$key};
            }
        }

        my $sbin_files = $self->{'properties'}->{'sbin_files'};
        foreach my $key ( keys %{$sbin_files} ) {
            if ( -f $sbin_files->{$key} ) {
                printf "Removing %s\n", $sbin_files->{$key};
                unlink $sbin_files->{$key};
            }
        }

        my $etc_files = $self->{'properties'}->{'etc_files'};
        foreach my $key ( keys %{$etc_files} ) {
            if ( -f $etc_files->{$key} ) {
                printf "Removing %s\n", $etc_files->{$key};
                unlink $etc_files->{$key};
            }
        }
    }

    sub process_sbin_files {
        my $self = shift;

        use Digest::SHA;

        if ( $self->invoked_action() eq 'install' ) {
            my $files = $self->{'properties'}->{'sbin_files'};
            while ( my ( $src, $dst ) =  each %$files ) {
                $src = $self->base_dir() . '/' . $src;
                if ( -f $dst ) {
                    my $src_sum = Digest::SHA->new(256)->addfile($src)->hexdigest();
                    my $dst_sum = Digest::SHA->new(256)->addfile($dst)->hexdigest();
                    if ( $src_sum eq $dst_sum ) {
                        if ( defined $self->{'properties'}->{'verbose'} ) {
                            printf "Skipping %s (unchanged)\n", $dst;
                        }
                        next;
                    }
                }
                printf "Installing %s\n", $dst;
                File::Copy::copy( $src, $dst);
            }
        }
    }

    sub process_etc_files {
        my $self = shift;

        use Digest::SHA;

        if ( $self->invoked_action() eq 'install' ) {
            my $files = $self->{'properties'}->{'etc_files'};
            while ( my ( $src, $dst ) =  each %$files ) {

                if ( -f $dst ) {
                    if ( defined $self->{'properties'}->{'verbose'} ) {
                        printf "Skipping %s (pre-existing)\n", $dst;
                    }
                    next;
                }

                printf "Installing %s\n", $dst;
                File::Copy::copy( $self->base_dir() . '/' . $src, $dst);
            }

            # Search for POD and create man5 pages
            use Pod::Man;
            use Pod::Find qw(pod_find);
            use File::Basename;
            my $man5dir      = '/usr/share/man/man5';
            my $dist_version = $self->dist_version();
            my %pods = pod_find({},( $self->base_dir() . '/etc'));
            foreach my $pod ( keys %pods ) {
                my $pod_rel = $pod;
                my $base_dir = $self->base_dir();
                $pod_rel =~ s/${base_dir}\///mx;
                my $man5page = $man5dir . '/' . basename($pod, '.pod') . '.5';
                printf "Manifying %s -> %s\n", $pod_rel, $man5page;
                my $parser = Pod::Man->new(
                    release => "MyTOTP v$dist_version", section => 5
                );
                $parser->parse_from_file( $pod, $man5page );
            }
        }
    }
EOF

my $build = $class->new(
    dist_name         => 'MyTOTP',
    module_name       => 'MyTOTP',
    dist_version      => $VERSION,
    dist_author       => 'Bennett Samowich <bennett@foolean.org>',
    dist_abstract     => 'Time-Based One-Time Password (TOTP) system',
    extra_manify_args => { release => "MyTOTP v$VERSION" },
    license           => 'GNUv3',
    installdirs       => 'vendor',
    bin_files         => {
        'bin/mytotpadm' => '/usr/bin/mytotpadm',
    },
    sbin_files => {
        'sbin/mytotp_freeradius.pl' => '/usr/sbin/mytotp_freeradius.pl',
    },
    etc_files => {
        'etc/mytotp.conf' => '/etc/mytotp/mytotp.conf',
    },
    requires => {
        'Config::General' => 0,
        'Crypt::CBC'      => 0,
        'Crypt::Rijndael' => 0,
        'Data::Dumper'    => 0,
        'DBI'             => 0,
        'Digest::SHA'     => 0,
        'English'         => 0,
        'File::Basename'  => 0,
        'Getopt::Long'    => 0,
        'Net::Domain'     => 0,
        'Net::LDAPS'      => 0,
        'POSIX'           => 0,
        'Readonly'        => 0,
        'Sys::Syslog'     => 0,
        'Term::ReadKey'   => 0,
        'Time::Local'     => 0,
    },
    build_requires => {
        'English'            => 0,
        'File::Spec'         => 0,
        'POSIX'              => 0,
        'Readonly'           => 0,
        'Test::Exit'         => 0,
        'Test::More'         => 0,
        'Test::Output'       => 0,
        'Test::Perl::Critic' => '>= 1.01',
    },
);

#my $install_base = $build->install_base();
#$build->install_base( 'bin' => $install_base . '/bin' );
#$build->install_base( 'doc' => $install_base . '/doc' );
#$build->install_base( 'etc' => $install_base . '/etc' );
#$build->install_base( 'lib' => $install_base . '/lib' );

$build->add_build_element('etc');
$build->add_build_element('bin');
$build->add_build_element('sbin');
$build->create_build_script;

# Announce what the user is to do next
printf "\nTo install '%s' 'v%s', run:\n",
  $build->dist_name(), $build->dist_version();
printf "\t./Build\n";
printf "\t./Build test\n";
printf "\t./Build install\n";
