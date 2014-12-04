# == Class: sudoers::sudo
#
class sudoers::sudo(
  $ensure          = 'present',
  $pkgname         = 'sudo',
  $altname         = 'sudo',
  $sudo_adminfile  = undef,
  $sudo_pkg_source = undef,
  $provider        = undef,
) {

  # validate params
  if $sudo_adminfile != undef {
    validate_absolute_path($sudo_adminfile)
  }

  if $provider != undef {
    validate_re($provider, '^[a-zA-Z0-9]+[a-zA-Z0-9_]+$', "sudoers::sudo::provider is <${provider}>, which does not match regex for an acceptable name.")
  }

  if $sudo_pkg_source != undef {
    validate_absolute_path($sudo_pkg_source)
  }

  package { $pkgname :
    ensure    => $ensure,
    alias     => $altname,
    adminfile => $sudo_adminfile,
    source    => $sudo_pkg_source,
    provider  => $provider,
  }

  if $::osfamily != 'Solaris' {
    file { '/bin/sudo' :
      ensure  => link,
      target  => '/usr/bin/sudo',
      require => Package[$pkgname],
    }
  }
}
