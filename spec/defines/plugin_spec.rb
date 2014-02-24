require 'spec_helper'

describe 'sudoers::deploy_sudoers' do
  context 'should create /etc/sudoers file' do
    let(:title) { '/etc/sudoers' }
    let(:params) {
      { :check_target  => '/etc/sudoers.d/._check_~', }
    }

    it {
      should contain_file('/etc/sudoers').with({
        'ensure'    => 'present',
        'path'      => '/etc/sudoers',
# 1)    'mode'      => '0440',
        'subscribe' => 'Exec[check_sudoers_cmd]',
      })
    }

  end
end


# 1) value for mode is taken from sudoers::mode. No clue how to source it from there :(
#    Alternate approach: parameterize it
