require 'spec_helper'
describe 'sudoers' do

context 'setting sudoers::source to <for_spec_testing_only> to serve as fake source of sudoers rules' do
  let(:params) { { :source => 'for_spec_testing_only' } }

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
      it { should contain_file('check_sudoers_file').with_content(/# for spec testing only, if you see this in real life you are in a mess!$/) }

      it {
        should contain_exec('check_sudoers_cmd').with({
          'command'     => 'visudo -cf /etc/sudoers.d/._check_~ && cp -p /etc/sudoers.d/._check_~ /etc/sudoers.d/._check_~.ok',
          'path'        => '/bin:/usr/bin:/sbin:/usr/sbin:/opt/csw/sbin:/opt/quest/sbin:/app/sudo/1.8.6p8/bin:/app/sudo/1.8.6p8/sbin',
          'refreshonly' => 'true',
          'notify'      => 'Exec[sudoers_cleanup_cmd]',
        })
      }

      it {
        should contain_exec('sudoers_cleanup_cmd').with({
          'command'     => '/bin/rm -f /etc/sudoers.d/._check_~',
          'path'        => '/bin:/usr/bin:/sbin:/usr/sbin:/opt/csw/sbin:/opt/quest/sbin:/app/sudo/1.8.6p8/bin:/app/sudo/1.8.6p8/sbin',
          'refreshonly' => 'true',
        })
      }
    end

    context 'with sudoers::hiera_merge set to invalid value <invalid>' do
      let(:params) { { :hiera_merge => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('sudoers')
        }.to raise_error(Puppet::Error,/sudoers::hiera_merge may be either 'true' or 'false' and is set to <invalid>./)
      end
    end

    context 'with sudoers::source set to invalid value <invalid>' do
      let(:params) { { :source => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('sudoers')
        }.to raise_error(Puppet::Error,/Sorry, I don\'t know how to handle invalid yet./)
      end
    end


  end
end
