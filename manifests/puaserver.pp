# == Class: sudoers::puaserver
#
class sudoers::puaserver(
  $owner         = 'root',
  $group         = 'root',
  $puatopdir     = '/srv/eis',
  $puaheadercmd  = 'cat sudo/sudo.aliases',
  $puaextractcmd = 'sudoers3',
) {

  file { '/opt/eis_pua' :
    ensure => 'directory',
    owner  => $owner,
    group  => $group,
    mode   => '0755',
  } ->
  file { '/opt/eis_pua/bin' :
    ensure => 'directory',
    owner  => $owner,
    group  => $group,
    mode   => '0755',
  } ->
  file { '/opt/eis_pua/bin/serve' :
    ensure  => 'file',
    owner   => $owner,
    group   => $group,
    mode    => '0755',
    content => template( 'sudoers/serve.erb' )
  }

  file { '/var/run/pua' :
    ensure => 'directory',
    owner  => $owner,
    group  => $group,
    mode   => '0755',
  }

}
