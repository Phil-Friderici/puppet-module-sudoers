# == Define: sudoers::frag
#
define sudoers::frag (
  $path = '',
  $prio = '10',
) {

  include sudoers::file
  $frag = "/etc/sudoers.d/${prio}_part"

  file {  $frag :
    source => $path,
    notify => Exec ["check_sudoers_${frag}"],
  }

  exec { "check_sudoers_${frag}" :
    command     => "visudo -cf ${frag}",
    path        => $frag,
    refreshonly => true,
    notify      => Exec ['create_sudoers'],
  }

}
