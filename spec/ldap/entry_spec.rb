require 'spec_helper'

describe Net::LDAP::Entry do
  
  before do
    @entry = Net::LDAP::Entry.from_single_ldif_string(
      %Q{dn: something
foo: foo
barAttribute: bar
      }
    )
  end
  
  subject { @entry }
  
  it { should respond_to :dn }
  
  context "sugary data accessors" do
    it { should respond_to :foo }
    it { should respond_to :Foo }
    it { should respond_to :foo= }
    specify { @entry.foo.should eq ['foo'] }
    specify { @entry.Foo.should eq ['foo'] }
    specify { @entry.foo = "bar"; @entry.foo.should eq ['bar'] }
    specify { @entry.fOo = "bar"; @entry.fOo.should eq ['bar'] }    
  end

end