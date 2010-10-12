require 'spec_helper'
require 'live_helper'

describe Net::LDAP do
  let(:basedn) { set_base_dn }
  let(:connection_options) { conn_parameters }
  let(:auth_options) { auth_parameters }
  
  context "when opening a connection" do
    Net::LDAP.open(connection_options)
  end
end