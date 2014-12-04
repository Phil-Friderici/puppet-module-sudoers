# Class sudoers
#   - Handle sudoers file
# ===

class sudoers(
  $hiera_merge       = false,
  $target            = '/etc/sudoers',
  $target_dir        = '/etc/sudoers.d',
  $target_file       = '._check_~',
  $path              = '/bin:/usr/bin:/sbin:/usr/sbin:/opt/csw/sbin:/opt/quest/sbin:/app/sudo/1.8.6p8/bin:/app/sudo/1.8.6p8/sbin',
  $preamble          = '',
  $epilogue          = '',
  $rule_source       = '/opt/eis_pua/bin/fetch2.pl',
  $owner             = 'root',
  $group             = 'root',
  $mode              = '0440',
  $vas_plugin_enable = false,
  $vas_plugin_path   = '',
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
    $epilogue_real = hiera_array('sudoers::epilogue')
    validate_array($preamble_real)
    validate_array($epilogue_real)
  } else {
    $preamble_real = $preamble
    $epilogue_real = $epilogue
    validate_string($preamble_real)
    validate_string($epilogue_real)
    notice('Future versions of the sudoers module will default sudoers::hiera_merge to true')
  }

  case type($vas_plugin_enable) {
    'string': {
      validate_re($vas_plugin_enable, '^(true|false)$', "sudoers::vas_plugin_enable may be either 'true' or 'false' and is set to <${vas_plugin_enable}>.")
      $vas_plugin_enable_real = str2bool($vas_plugin_enable)
    }
    'boolean': {
      $vas_plugin_enable_real = $vas_plugin_enable
    }
    default: {
      $vas_plugin_enable_real = false
    }
  }

  if ($vas_plugin_enable_real == true) and (type($vas_plugin_path) == 'string') {
    if $vas_plugin_path == '' {
      case $::kernel {
        'Linux': {
          case $::architecture {
            'i386': {
              $vas_plugin_path_real = '/opt/quest/lib/libsudo_vas.so'
            }
            'x86_64', 'amd64': {
              $vas_plugin_path_real = '/opt/quest/lib64/libsudo_vas.so'
            }
            default: {
              fail("sudoers::vas_plugin_path - unknown default for architecture ${::architecture} on kernel ${::kernel}")
            }
          }
        }
        'SunOS': {
          $vas_plugin_path_real = '/opt/quest/lib/libsudo_vas.so'
        }
        default: {
          fail('sudoers::vas_plugin_path must be set, if running on unknown plattform!')
        }
      }
    }
    else {
      $vas_plugin_path_real = $vas_plugin_path
    }
  }
  else {
    $vas_plugin_path_real = ''
  }


  $check_target = "${target_dir}/${target_file}"
  $rules        = generate($rule_source, $::hostname, $::fqdn, $::ipaddress)
  $content      = template('sudoers/sudoers.erb')

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
    check_target => $check_target,
    mode         => $mode,
  }

}
