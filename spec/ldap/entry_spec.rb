require 'spec_helper'

describe Net::LDAP::Entry do
  
  let(:entry) do
    Net::LDAP::Entry.from_single_ldif_string(
      %Q{dn: something
foo: foo
barAttribute: bar
      }
    )
  end
  
  subject { entry }
  
  it { should respond_to :dn }
  it { should respond_to :foo }
  it { should respond_to :Foo }
  it { should respond_to :foo= }
  its(:foo) { should eq ['foo'] }
  its(:Foo) { should eq ['foo'] }
  specify { entry.foo = "bar"; entry.foo.should eq ['bar'] }
  specify { entry.fOo = "bar"; entry.fOo.should eq ['bar'] }    

end