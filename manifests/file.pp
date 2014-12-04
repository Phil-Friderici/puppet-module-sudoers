# == Class: sudoers::file
#
class sudoers::file {

  exec { 'create_sudoers' :
    command     => '/bin/cat * > /etc/sudoers',
    refreshonly => true,
  }

}
