# eis_main_interface.rb

Facter.add('eis_main_interface') do
  setcode do
    begin
      main_interface = `netstat -r | awk '/^default/ { print $NF }'`
    rescue
      main_interface = 'none'
    end

    main_interface
  end
end

Facter.add('eis_ipaddress_main_interface') do
  setcode do
    begin
      main_interface = Facter.value(:eis_main_interface).strip

      response = Facter.value("ipaddress_#{main_interface}").strip
    rescue
      response = 'none'
    end

    response
  end
end
