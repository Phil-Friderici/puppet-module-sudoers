# == Class: sudoers::puppetmaster
#
class sudoers::puppetmaster(
  $puaserver  = undef,
  $puauser    = undef,
  $puacommand = undef,
  $usessh     = 1,
  $keypath    = undef,
  $fetcher    = 'fetch2.pl',
) {

  file { '/opt/eis_pua' :
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  } ->
  file { '/opt/eis_pua/bin' :
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  if $fetcher in [ 'fetch2.pl', 'fetch' ] {
    file { 'fetcher' :
      ensure  => 'file',
      path    => "/opt/eis_pua/bin/${fetcher}",
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      content => template( "sudoers/${fetcher}.erb" ),
      require => File[ '/opt/eis_pua/bin' ],
    }
  } else {
    file { 'fetcher' :
      ensure  => 'file',
      path    => "/opt/eis_pua/bin/${fetcher}",
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      source  => $fetcher,
      require => File[ '/opt/eis_pua/bin' ],
    }
  }
}
