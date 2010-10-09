require 'spec_helper'

describe Net::LDAP::Filter do
  before(:all) { Filter = Net::LDAP::Filter }
  
  describe '#ex' do
    
    let(:filter) { Filter.ex 'foo', 'bar' }
    
    context "when converting filter" do
      subject { filter }   
      its(:to_s) { should eq '(foo:=bar)' }
    end
    
    context "when converting from string to rfc to string" do
      subject { Filter.from_rfc2254(filter.to_s) }
      it { should eq filter }
    end
    
    context "when converting to and from BER" do
      let(:ber) { filter.to_ber }
      subject { Filter.parse_ber(ber.read_ber(Net::LDAP::AsnSyntax)) }
      it { should eq filter }
    end
    
    context "when doing various legal filter inputs" do
      filters = [
        '(o:dn:=Ace Industry)', 
        '(:dn:2.4.8.10:=Dino)', 
        '(cn:dn:1.2.3.4.5:=John Smith)', 
        '(sn:dn:2.4.6.8.10:=Barbara Jones)', 
      ]
       
      for filter_str in filters
        before { @filter = Filter.from_rfc2254(filter_str) }
        
        context "\#from_rfc2254({#{@filter.to_s}})" do
          subject { @filter }
          it { should be_an_instance_of Filter }
        end
          
        context "when converting to and from BER" do
          let(:ber) { @filter.to_ber }
          subject { Filter.parse_ber(ber.read_ber(Net::LDAP::AsnSyntax)) }
          it { should eq @filter }
        end
          
      end
    end
  end
end