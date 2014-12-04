require 'spec_helper'

describe 'sudoers::file' do
  context 'with default options' do

    it { should compile.with_all_deps }

    it {
      should contain_exec('create_sudoers').with({
        'command'     => '/bin/cat * > /etc/sudoers',
        'refreshonly' => 'true',
      })
    }

  end
end
