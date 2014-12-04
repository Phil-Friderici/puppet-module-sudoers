require 'spec_helper'

describe 'sudoers::puppetmaster' do
  context 'with default options' do
    it { should compile.with_all_deps }

    it {
      should contain_file('/opt/eis_pua/bin').with({
        'ensure'  => 'directory',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
      })
    }

    it {
      should contain_file('fetcher').with({
        'ensure'  => 'file',
        'path'    => '/opt/eis_pua/bin/fetch2.pl',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
        'require' => 'File[/opt/eis_pua/bin]',
      })
    }
    it { should contain_file('fetcher').with_content(/^my\ \$usessh\ =\ 1;$/) }
    it { should contain_file('fetcher').with_content(/^my\ \$command\ =\ \(''\);$/) }
    it { should contain_file('fetcher').with_content(/^\ push\ @cmd,\ '-oUserKnownHostsFile=\/var\/lib\/puppet\/ssl\/puahostfile';$/) }
    it { should contain_file('fetcher').with_content(/^\ push\ @cmd,\ '-i';$/) }
    it { should contain_file('fetcher').with_content(/^\ push\ @cmd,\ '@';$/) }

  end

  context 'with default options and reasonable parameters' do
    let(:params) do
      {
        :puaserver  => 'puaserver.localdomain',
        :puauser    => 'puauser',
        :puacommand => '/bin/echo',
        :keypath    => '/tmp/id_rsa',
      }
    end

    it { should compile.with_all_deps }

    it {
      should contain_file('/opt/eis_pua/bin').with({
        'ensure'  => 'directory',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
      })
    }

    it {
      should contain_file('fetcher').with({
        'ensure'  => 'file',
        'path'    => '/opt/eis_pua/bin/fetch2.pl',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
        'require' => 'File[/opt/eis_pua/bin]',
      })
    }
    it { should contain_file('fetcher').with_content(/^my\ \$usessh\ =\ 1;$/) }
    it { should contain_file('fetcher').with_content(/^my\ \$command\ =\ \('\/bin\/echo'\);$/) }
    it { should contain_file('fetcher').with_content(/^\ push\ @cmd,\ '-oUserKnownHostsFile=\/var\/lib\/puppet\/ssl\/puahostfile';$/) }
    it { should contain_file('fetcher').with_content(/^\ push\ @cmd,\ '-i\/tmp\/id_rsa';$/) }
    it { should contain_file('fetcher').with_content(/^\ push\ @cmd,\ 'puauser@puaserver.localdomain';$/) }

  end

  context 'with fetcher = <fetch>' do
    let(:params) do
      {
        :fetcher    => 'fetch',
        :puaserver  => 'puaserver.localdomain',
        :puauser    => 'puauser',
        :puacommand => '/bin/echo',
        :keypath    => '/tmp/id_rsa',
      }
    end

    it { should compile.with_all_deps }

    it {
      should contain_file('/opt/eis_pua/bin').with({
        'ensure'  => 'directory',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
      })
    }

    it {
      should contain_file('fetcher').with({
        'ensure'  => 'file',
        'path'    => '/opt/eis_pua/bin/fetch',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
        'require' => 'File[/opt/eis_pua/bin]',
      })
    }
    it { should contain_file('fetcher').with_content(/^ssh\ puauser\@puaserver.localdomain\ -i\ \/tmp\/id_rsa "\/bin\/echo\ \$\@"$/) }

  end



end
