module Net::BER::Extensions::FalseClass
  def to_ber
    "\001\001\000"
  end
end
