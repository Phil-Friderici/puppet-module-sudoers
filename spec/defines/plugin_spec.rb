require 'spec_helper'

describe 'sudoers::deploy_sudoers' do
  context 'should create /etc/sudoers file' do
    let(:title) { '/etc/sudoers' }
    let(:params) do
      {
        :check_target  => '/etc/sudoers.d/._check_~',
        :mode          => '0440',
      }
    end

    it {
      should contain_file('/etc/sudoers').with({
        'ensure'    => 'present',
        'path'      => '/etc/sudoers',
        'mode'      => '0440',
        'subscribe' => 'Exec[check_sudoers_cmd]',
      })
    }

  end
end
