require 'spec_helper'

describe 'sudoers::sudo' do
  context 'with default options on RedHat' do
    let :facts do
      {
        :osfamily => 'RedHat',
      }
    end

    it { should compile.with_all_deps }

    it {
      should contain_package('sudo').with({
        'ensure'  => 'present',
        'alias'   => 'sudo',
      })
    }

    it {
      should contain_file('/bin/sudo').with({
        'ensure'  => 'link',
        'target'  => '/usr/bin/sudo',
        'require' => 'Package[sudo]',
      })
    }

  end

  context 'with default options on Solaris' do
    let :facts do
      {
        :osfamily => 'Solaris',
      }
    end

    it { should compile.with_all_deps }

    it {
      should contain_package('sudo').with({
        'ensure'  => 'present',
        'alias'   => 'sudo',
      })
    }

  end
end
