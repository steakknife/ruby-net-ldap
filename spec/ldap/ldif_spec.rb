require 'spec_helper'
require 'base64'

describe Net::LDAP::Dataset do
  
  before { Dataset = Net::LDAP::Dataset }
  
  context "when reading null LDIF" do
    subject { Dataset.read_ldif(StringIO.new) }
    it { should be_empty }
  end
  
  context "when reading LDIF with comments" do
    before { @str = ["# Hello from LDIF-land", "# This is an unterminated comment"] }
    subject { Dataset.read_ldif( StringIO.new(@str.join("\r\n")) ).comments }
    it { should eq @str }
  end
  
  context "when reading LDIF with passwords" do
    before do 
      @psw = "{SHA}" + Base64::encode64(Digest::SHA1.digest("goldbricks")).chomp
      ldif_encoded = Base64::encode64(@psw).chomp
      @ds = Dataset.read_ldif(StringIO.new("dn: Goldbrick\r\nuserPassword:: #{ldif_encoded}\r\n\r\n"))
    end
    
    subject { @ds["Goldbrick"][:userpassword].shift }
    it { should eq @psw }    
  end
  
  context "when reading LDIF with extra spaces" do
    subject { Dataset.read_ldif(StringIO.new("dn: abcdefg\r\n   hijklmn\r\n\r\n")) }
    it { should have_key "abcdefg hijklmn" }
  end
    
end