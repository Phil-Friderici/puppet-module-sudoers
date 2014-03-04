# Class sudoers
#   - Handle sudoers file
# ===

class sudoers(
  $hiera_merge  = false,
  $target       = '/etc/sudoers',
  $source       = 'PUA',
  $target_dir   = '/etc/sudoers.d',
  $target_file  = '._check_~',
  $path         = '/bin:/usr/bin:/sbin:/usr/sbin:/opt/csw/sbin:/opt/quest/sbin:/app/sudo/1.8.6p8/bin:/app/sudo/1.8.6p8/sbin',
  $preamble     = '',
  $fetcher      = 'fetch2.pl',
  $owner        = 'root',
  $group        = 'root',
  $mode         = '0440',
) {

  case type($hiera_merge) {
    'string': {
      validate_re($hiera_merge, '^(true|false)$', "sudoers::hiera_merge may be either 'true' or 'false' and is set to <${hiera_merge}>.")
      $hiera_merge_real = str2bool($hiera_merge)
    }
    'boolean': {
      $hiera_merge_real = $hiera_merge
    }
    default: {
      fail('sudoers::hiera_merge type must be true or false.')
    }
  }

  if $hiera_merge_real == true {
    $preamble_real = hiera_array('sudoers::preamble')
    validate_array($preamble_real)
  } else {
    $preamble_real = $preamble
    validate_string($preamble_real)
    notice('Future versions of the sudoers module will default sudoers::hiera_merge to true')
  }

  $check_target = "${target_dir}/${target_file}"

  case $source {
    'PUA' : {
      $rules = generate( "/opt/eis_pua/bin/${fetcher}", $::hostname, $::fqdn, $::ipaddress)
      $content = template( 'sudoers/sudoers.erb' )
    }
    'for_spec_testing_only' : {
      $rules = "# for spec testing only, if you see this in real life you are in a mess!"
      $content = template( 'sudoers/sudoers.erb' )
    }
    default : {
      fail( "Sorry, I don't know how to handle ${source} yet." )
    }
  }

  file { $target_dir :
    ensure => directory,
    owner  => $owner,
    group  => $group,
    notify => File [ 'check_sudoers_file' ],
  }

  file { 'check_sudoers_file' :
    ensure  => 'present',
    path    => $check_target,
    owner   => $owner,
    group   => $group,
    mode    => $mode,
    content => $content,
    notify  => Exec[ 'check_sudoers_cmd' ],
  }

  exec { 'check_sudoers_cmd' :
    command     => "visudo -cf ${check_target} && cp -p ${check_target} ${check_target}.ok",
    path        => $path,
    refreshonly => true,
  }

  deploy_sudoers { $target :
    check_target => $check_target
  }

}
