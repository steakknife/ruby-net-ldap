require 'spec_helper'
require 'net/snmp'

describe Net::SNMP do

    before do
      @snmp_get_request = "0'\002\001\000\004\006public\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000"
    end
    
    it "will fail on invalid packets" do
      "xxxx".read_ber(Net::SNMP::AsnSyntax).should raise_error
    end
    
    it "should self modify strings from BER" do
      data = "xxx"
      (data.read_ber!).should be nil
      data.should == "xxx"

      data = @snmp_get_request + "!!!"
      ary = data.read_ber!(Net::SNMP::AsnSyntax)
      
      data.should_be == "!!!"
      ary.should_be_an_instance_of Array
      ary.should_be_an_instance_of Net::BER:BerIdentifiedArray
    end
end