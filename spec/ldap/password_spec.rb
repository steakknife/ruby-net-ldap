require 'spec_helper'

describe Net::LDAP::Password do
  before(:all) { Password = Net::LDAP::Password }
  context "when making a MD5 hash" do
    subject { Password.generate :md5, 'cashflow' }
    it { should eq "{MD5}xq8jwrcfibi0sZdZYNkSng==" }
  end
    
  context "when making a SHA1 hash" do
    subject { Password.generate :sha, 'cashflow' }
    it { should eq "{SHA}YE4eGkN4BvwNN1f5R7CZz0kFn14=" }
  end
end