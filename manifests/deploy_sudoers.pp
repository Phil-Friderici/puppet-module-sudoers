# == Define: sudoers::deploy_sudoers
#
#  rollout sudoers file(s)
#
define sudoers::deploy_sudoers (
  $check_target,
  $mode,
) {
  file { $name :
    ensure    => present,
    path      => $name,
    mode      => $mode,
    source    => "${check_target}.ok",
    subscribe => Exec[ 'check_sudoers_cmd' ],
  }
}
