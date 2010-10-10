require 'spec_helper'
require 'live_helper'

describe Net::LDAP do
  let(:basedn) { set_base_dn }
  let(:connection_options) { conn_parameters }
  let(:auth_options) { auth_parameters }
  let(:conn) { Net::LDAP.open(connection_options) }
  before(:each) { conn.bind(auth_options) }
  
  context "when creating new objects" do
    conn.
  end
  
  context "when destroying objects" do
    
  end
end