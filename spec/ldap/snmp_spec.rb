require 'spec_helper'
require 'net/snmp'

describe Net::SNMP::Counter32 do
  subject {Net::SNMP::Counter32.new(100)}
  its(:to_ber) { should eq "A\001d" }
end
  
describe Net::SNMP::Gauge32 do
  subject {Net::SNMP::Gauge32.new(100)}
  its(:to_ber) { should eq "B\001d"}
end

describe Net::SNMP::TimeTicks32 do
  subject {Net::SNMP::TimeTicks32.new(100)}
  its(:to_ber) {should eq "C\001d"}
end

describe Net::SnmpPdu do
  
  it "should raise exception on invalid data" do
    lambda { Net::SnmpPdu.parse("aaaaaaaaaaaaaa")}.should raise_error(Net::SnmpPdu::Error)
  end
  
  it "should raise an error on an empty string" do
    lambda { Net::SnmpPdu.new.to_ber_string.should raise_error(Net::SnmpPdu::Error) }
  end
  
  context "when sending a request packet" do
    let(:snmp_get_request) {"0'\002\001\000\004\006public\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000"}
    let(:packet) { snmp_get_request.read_ber(Net::SNMP::AsnSyntax) }
    specify { packet.should be_an_instance_of Net::BER::BerIdentifiedArray }
    specify { packet.ber_identifier.should eq 48 }
    context "when parsing a PDU packet" do
      subject { Net::SnmpPdu.parse(packet) }
      its(:pdu_type) { should eq :get_request }
      its(:request_id) { should eq 16170 }
      its(:variables) { should eq [[[1, 3, 6, 1, 2, 1, 1, 1, 0], nil]] }
    end
  end
  
  context "when making a bad request" do
    subject { Net::SnmpPdu.new }
    specify { lambda {subject.to_ber_string}.should raise_error Net::SnmpPdu::Error }
  end
  
  
  context "when creating a malformed PDU type" do
    subject { Net::SnmpPdu.new }
    specify { lambda{subject.version = 100}.should raise_error Net::SnmpPdu::Error }
    specify { lambda{subject.pdu_type = :nothing }.should raise_error Net::SnmpPdu::Error }
  end
  
  context "when setting the community" do
    let(:snmp_get_request_xxx) {"0'\002\001\000\004\006xxxxxx\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000"}
    subject {Net::SnmpPdu.parse(snmp_get_request_xxx.read_ber(Net::SNMP::AsnSyntax))}
    its(:community) { should eq "xxxxxx" }
  end
  
  context "when making a response" do
    let(:snmp_get_response) {"0+\002\001\000\004\006public\242\036\002\002'\017\002\001\000\002\001\0000\0220\020\006\b+\006\001\002\001\001\001\000\004\004test"}
    before do
      @pdu = Net::SnmpPdu.new
      @pdu.version = 0
      @pdu.community = "public"
      @pdu.pdu_type = :get_response
      @pdu.request_id = 9999
      @pdu.error_status = 0
      @pdu.error_index = 0
      @pdu.add_variable_binding [1, 3, 6, 1, 2, 1, 1, 1, 0], "test"
    end
    subject { @pdu }
    its(:to_ber_string) { should eq snmp_get_response }
  end
  
end