require 'stringio'

module Net::BER::Extensions::String
  # A universal octet-string is tag number 4, but others are possible
  # depending on the context, so we let the caller give us one. The
  # preferred way to do this in user code is via #to_ber_application_string
  # and #to_ber_contextspecific.
  def to_ber(code = 4)
    [code].pack('C') + length.to_ber_length_encoding + self
  end

  # Creates a application-specific BER string encoded value.
  def to_ber_application_string(code)
    to_ber(0x40 + code)
  end

  # Creates a context-specific BER string encoded value.
  def to_ber_contextspecific(code)
    to_ber(0x80 + code)
  end

  # Nondestructively reads a BER object from this string.
  def read_ber(syntax = nil)
    StringIO.new(self).read_ber(syntax)
  end

  # Destructively reads a BER object from this string.
  def read_ber!(syntax = nil)
    obj, consumed = read_ber_from_string(self, syntax)
    if consumed
      self.slice!(0...consumed)
      obj
    else
      nil
    end
  end
end
