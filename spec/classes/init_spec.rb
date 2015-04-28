require 'spec_helper'

# in real life :rule_source point to a PUA server which delivers the sudoers rules
# for testing we can use these fake generators:
# /bin/true = output will be empty and pass visudo validation
# /bin/echo = output will be ':hostname :fqdn :ipaddress' and will not pass visudo validation

describe 'sudoers' do
  let :facts do
    {
      :hostname  => 'localhost',
      :fqdn      => 'localhost.localdomain',
      :ipaddress => '127.0.0.1',
    }
  end

  context 'with default options' do
    let :params do
      {
        :rule_source => '/bin/true',
      }
    end

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
        'content' => "#\n# THIS FILE IS MAINTAINED BY PUPPET\n# INTERNET IS FULL. GO AWAY!!\n#\n\n\n\n\n",
      })
    }

    it {
      should contain_exec('check_sudoers_cmd').with({
        'command'     => 'visudo -cf /etc/sudoers.d/._check_~ && cp -p /etc/sudoers.d/._check_~ /etc/sudoers.d/._check_~.ok',
        'path'        => '/bin:/usr/bin:/sbin:/usr/sbin:/opt/csw/sbin:/opt/quest/sbin:/app/sudo/1.8.6p8/bin:/app/sudo/1.8.6p8/sbin',
        'refreshonly' => 'true',
      })
    }
    it { should_not contain_file('check_sudoers_file').with_content(/^Defaults group_plugin=/) }
  end

  context 'with failhard set to <true> and a valid sudoers file' do
    let :params do
      {
        :rule_source => '/bin/true',
        :failhard    => true,
      }
    end

    it { should compile.with_all_deps }
    it { should contain_class('sudoers') }
  end

  context 'with failhard set to <true> and an invalid sudoers file' do
    # use /bin/echo as fake generator for sudoers rules. Output will be ':hostname :fqdn :ipaddress' and will not pass validation.
    let :params do
      {
        :rule_source => '/bin/echo',
        :failhard    => true,
      }
    end

    it 'should fail' do
      expect {
        should contain_class('sudoers')
      }.to raise_error(Puppet::Error,/^visudo failed to validate sudoers content/)
    end
  end

  context 'with preamble set to <Defaults requiretty>' do
    let :params do
      {
        :rule_source => '/bin/echo',
        :preamble    => 'Defaults requiretty',
      }
    end

    it { should contain_file('check_sudoers_file').with_content(/^Defaults requiretty$/) }

  end

  context 'with epilogue set to <Defaults:xymon !requiretty>' do
    let :params do
      {
        :rule_source => '/bin/echo',
        :epilogue    => 'Defaults:xymon !requiretty',
      }
    end

    it { should contain_file('check_sudoers_file').with_content(/^Defaults:xymon !requiretty$/) }

  end

  # test for preamble first, epilogue afterwards
  context 'with preamble set to <Defaults requiretty> and epilogue set to <Defaults:xymon !requiretty>' do
    let :params do
      {
        :rule_source => '/bin/echo',
        :preamble    => 'Defaults requiretty',
        :epilogue    => 'Defaults:xymon !requiretty',
      }
    end

    it { should contain_file('check_sudoers_file').with_content(/^Defaults requiretty$\n.*\n*^Defaults:xymon \!requiretty$/) }

  end

  # test for vas_plugin_enable to accept true and false as booleans and strings
  ['true','false',true,false,'invalid'].each do |value|
    context "where vas_plugin_enable set to <#{value}> and vas_plugin_path set to </tmp/pseudolib_vas.so>" do

      let :params do
        {
          :rule_source       => '/bin/true',
          :vas_plugin_enable => "#{value}",
          :vas_plugin_path   => '/tmp/pseudolib_vas.so',
        }
      end

      if value == true or value == 'true' then
        it { should contain_file('check_sudoers_file').with_content(/^Defaults group_plugin=\"\/tmp\/pseudolib_vas.so\"$/) }
      elsif value == false or value == 'false' then
        it { should_not contain_file('check_sudoers_file').with_content(/^Defaults group_plugin=$/) }
      else
        it 'should fail' do
          expect {
            should contain_class('sudoers')
          }.to raise_error(Puppet::Error,/^sudoers::vas_plugin_enable may be either 'true' or 'false' and is set to <invalid>./)
        end
      end
    end
  end

  platforms = {
    'Linux_i386' =>
      {
        :architecture            => 'i386',
        :kernel                  => 'Linux',
        :error_message           => '',
        :vas_plugin_path_default => '/opt/quest/lib/libsudo_vas.so',
      },
    'Linux_x86_64' =>
      {
        :architecture            => 'x86_64',
        :kernel                  => 'Linux',
        :error_message           => '',
        :vas_plugin_path_default => '/opt/quest/lib64/libsudo_vas.so',
      },
    'Linux_amd64' =>
      {
        :architecture            => 'amd64',
        :kernel                  => 'Linux',
        :error_message           => '',
        :vas_plugin_path_default => '/opt/quest/lib64/libsudo_vas.so',
      },
    'Linux_invalid' =>
      {
        :architecture            => 'invalid',
        :kernel                  => 'Linux',
        :error_message           => 'sudoers::vas_plugin_path - unknown default for architecture invalid on kernel Linux',
        :vas_plugin_path_default => '',
      },
    'SunOS_unknown' =>
      {
        :architecture            => 'unknown',
        :kernel                  => 'SunOS',
        :error_message           => '',
        :vas_plugin_path_default => '/opt/quest/lib/libsudo_vas.so',
      },
    'unknown_unknown' =>
      {
        :architecture            => 'unknown',
        :kernel                  => 'unknown',
        :error_message           => 'sudoers::vas_plugin_path must be set, if running on unknown plattform!',
        :vas_plugin_path_default => '',
      },
  }

  # test for kernel/architecture specific vas_plugin_path
  describe 'where vas_plugin_enable set to <true> and vas_plugin_path has no given value' do
    platforms.sort.each do |k,v|
      context "on <#{v[:kernel]}> with <#{v[:architecture]}> architecture" do
        let :facts do
          {
            :architecture => v[:architecture],
            :kernel       => v[:kernel],
          }
        end
        let :params do
          {
            :rule_source       => '/bin/true',
            :vas_plugin_enable => true,
          }
        end

        if v[:error_message] == ''
          it { should contain_file('check_sudoers_file').with_content(/^Defaults group_plugin=\"#{v[:vas_plugin_path_default]}\"$/) }
        else
          it 'should fail' do
            expect {
              should contain_class('sudoers')
            }.to raise_error(Puppet::Error,/^#{v[:error_message]}/)
          end
        end

      end
    end
  end

  # test for given vas_plugin_path
  describe 'where vas_plugin_enable set to <true> and vas_plugin_path set to </tmp/pseudolib_vas.so>' do
    platforms.sort.each do |k,v|
      context "on <#{v[:kernel]}> with <#{v[:architecture]}> architecture" do
        let :params do
          {
            :rule_source       => '/bin/true',
            :vas_plugin_enable => true,
            :vas_plugin_path   => '/tmp/pseudolib_vas.so',
          }
        end

        it { should contain_file('check_sudoers_file').with_content(/^Defaults group_plugin=\"\/tmp\/pseudolib_vas.so\"$/) }

      end
    end
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
