module Net::BER::Extensions::Array
  # Converts the Array to a BER sequence.
  def to_ber(id = 0)
    to_ber_seq_internal(0x30 + id)
  end

  # Converts the Array to a BER set.
  def to_ber_set(id = 0)
    to_ber_seq_internal(0x31 + id)
  end

  # Converts the Array to a BER sequence.
  def to_ber_sequence(id = 0)
    to_ber_seq_internal(0x30 + id)
  end

  # An application-specific sequence usually gets assigned a tag that is
  # meaningful to the particular protocol being used. This is different from
  # the universal sequence, which usually gets a tag value of 16.
  #
  # Now here's an interesting thing: We're adding the X.690 "application
  # constructed" code at the top of the tag byte (0x60), but some clients,
  # notably ldapsearch, send "context-specific constructed" (0xA0). The
  # latter would appear to violate RFC-1777, but what do I know? We may need
  # to change this.
  def to_ber_appsequence(id = 0)
    to_ber_seq_internal(0x60 + id)
  end

  # Converts the Array to a context-specific BER sequence.
  def to_ber_contextspecific(id = 0)
    to_ber_seq_internal(0xA0 + id)
  end

  # Converts the Array to an OID BER sequence.
  def to_ber_oid
    ary = self.dup
    first = ary.shift
    Net::BER.error.new("invalid OID") unless [0, 1, 2].include?(first)
    first = first * 40 + ary.shift
    ary.unshift first
    oid = ary.pack("w*")
    [6, oid.length].pack("CC") + oid
  end

  def to_ber_seq_internal(code)
    s = self.join
    [code].pack('C') + s.length.to_ber_length_encoding + s
  end
  private :to_ber_seq_internal
end
