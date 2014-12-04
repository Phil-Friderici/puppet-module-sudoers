require 'spec_helper'

describe 'sudoers::puaserver' do
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
      should contain_file('/var/run/pua').with({
        'ensure'  => 'directory',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
      })
    }

    it {
      should contain_file('/opt/eis_pua/bin/serve').with({
        'ensure'  => 'file',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0755',
      })
    }
    it { should contain_file('/opt/eis_pua/bin/serve').with_content(/^cd\ \/srv\/eis$/) }
    it { should contain_file('/opt/eis_pua/bin/serve').with_content(/^.\ bin\/activate$/) }
    it { should contain_file('/opt/eis_pua/bin/serve').with_content(/^cat\ sudo\/sudo.aliases$/) }
    it { should contain_file('/opt/eis_pua/bin/serve').with_content(/^python\ manage.py\ sudoers3 \$@$/) }

  end
end
