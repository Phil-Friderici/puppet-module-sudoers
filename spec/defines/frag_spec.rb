require 'spec_helper'

describe 'sudoers::frag' do
  context 'should create and check a fragment in /etc/sudoers.d/' do
    let(:title) { 'spec_test' }

    let(:params) do
      {
        :path  => '/tmp/spec_test',
      }
    end

    it { should contain_class('sudoers::file') }

    it {
      should contain_file('/etc/sudoers.d/10_part').with({
        'source' => '/tmp/spec_test',
        'notify' => 'Exec[check_sudoers_/etc/sudoers.d/10_part]',
      })
    }

    it {
      should contain_exec('check_sudoers_/etc/sudoers.d/10_part').with({
        'command'     => 'visudo -cf /etc/sudoers.d/10_part',
        'path'        => '/etc/sudoers.d/10_part',
        'refreshonly' => 'true',
        'notify'      => 'Exec[create_sudoers]',
      })
    }

  end
end
