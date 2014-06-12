require 'spec_helper'

describe 'sudoers' do
  let :facts do
    {
      :hostname  => 'localhost',
      :fqdn      => 'localhost.localdomain',
      :ipaddress => '127.0.0.1',
    }
  end

  # use /bin/echo as fake generator for sudoers rules. Output will become :hostname :fqdn :ipaddress
  let :params do
    { :rule_source => '/bin/echo' }
  end

  context 'with default options' do
    it { should compile.with_all_deps }
    it { should contain_class('sudoers') }

    it {
      should contain_file('/etc/sudoers.d').with({
        'ensure'  => 'directory',
        'owner'   => 'root',
        'group'   => 'root',
        'notify'  => 'File[check_sudoers_file]',
      })
    }

    it {
      should contain_file('check_sudoers_file').with({
        'ensure'  => 'present',
        'path'    => '/etc/sudoers.d/._check_~',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0440',
        'notify'  => 'Exec[check_sudoers_cmd]',
      })
    }
    it { should contain_file('check_sudoers_file').with_content(/^localhost localhost.localdomain 127.0.0.1$/) }

    it {
      should contain_exec('check_sudoers_cmd').with({
        'command'     => 'visudo -cf /etc/sudoers.d/._check_~ && cp -p /etc/sudoers.d/._check_~ /etc/sudoers.d/._check_~.ok',
        'path'        => '/bin:/usr/bin:/sbin:/usr/sbin:/opt/csw/sbin:/opt/quest/sbin:/app/sudo/1.8.6p8/bin:/app/sudo/1.8.6p8/sbin',
        'refreshonly' => 'true',
      })
    }
  end

  context 'with preamble set to <Defaults requiretty>' do
    let :params do
      {
        :rule_source => '/bin/echo',
        :preamble => 'Defaults requiretty',
      }
    end

    it { should contain_file('check_sudoers_file').with_content(/^Defaults requiretty$/) }

  end

  context 'with epilogue set to <Defaults:xymon !requiretty>' do
    let :params do
      {
        :rule_source => '/bin/echo',
        :epilogue => 'Defaults:xymon !requiretty',
      }
    end

    it { should contain_file('check_sudoers_file').with_content(/^Defaults:xymon !requiretty$/) }

  end

  # test for preamble first, epilogue afterwards
  context 'with preamble set to <Defaults requiretty> and epilogue set to <Defaults:xymon !requiretty>' do
    let :params do
      {
        :rule_source => '/bin/echo',
        :preamble  => 'Defaults requiretty',
        :epilogue  => 'Defaults:xymon !requiretty',
      }
    end

    it { should contain_file('check_sudoers_file').with_content(/^Defaults requiretty$\n.*\n*^Defaults:xymon \!requiretty$/) }

  end

  context 'with sudoers::hiera_merge set to invalid value <invalid>' do
    let(:params) { { :hiera_merge => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('sudoers')
      }.to raise_error(Puppet::Error,/sudoers::hiera_merge may be either 'true' or 'false' and is set to <invalid>./)
    end

  end

end
