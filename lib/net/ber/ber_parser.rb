require 'stringio'

module Net::BER::BERParser
  VERSION = '0.1.0'

  # The order of these follows the class-codes in BER.
  # Maybe this should have been a hash.
  TagClasses = [:universal, :application, :context_specific, :private]

  universal_primitive = {
    1 => :boolean,
    2 => :integer,
    4 => :string,
    5 => :null,
    6 => :oid,
    10 => :integer,
    13 => :string # (relative OID)
  }
  universal_constructed = {
    16 => :array,
    17 => :array
  }
  universal = {
    :primitive => universal_primitive,
    :constructed => universal_constructed
  }

  context_primitive = { 10 => :integer }
  context =  {
    :primitive => context_primitive
  }

  BuiltinSyntax = Net::BER.compile_syntax(:universal => universal,
                                          :context_specific => context)

  def parse_ber_object(id, type, syntax, newobj)
    # == is expensive so sort this so the common cases are at the top.
    obj = case type
          when :string
            s = Net::BER::BerIdentifiedString.new(newobj || "")
            s.ber_identifier = id
            s
          when :integer
            j = 0
            newobj.each_byte { |b| j = (j << 8) + b }
            j
          when :oid
            # Cf X.690 pgh 8.19 for an explanation of this algorithm.
            # Potentially not good enough. We may need a BerIdentifiedOid as
            # a subclass of BerIdentifiedArray, to get the ber identifier
            # and also a to_s method that produces the familiar dotted
            # notation.
            oid = newobj.unpack("w*")
            f = oid.shift
            g = if f < 40
                  [0, f]
                elsif f < 80
                  [1, f - 40]
                else
                  # f - 80 can easily be > 80. What a weird optimization.
                  [2, f - 80]
                end
            oid.unshift g.last
            oid.unshift g.first
            # Net::BER::BerIdentifiedOid.new(oid)
            oid
          when :array
            seq = Net::BER::BerIdentifiedArray.new
            seq.ber_identifier = id
            sio = StringIO.new(newobj || "")
            # Interpret the subobject, but note how the loop is built: nil
            # ends the loop, but false (a valid BER value) does not!
            while (e = sio.read_ber(syntax)) != nil
              seq << e
            end
            seq
          when :boolean
            newobj != "\000"
          when :null
            n = Net::BER::BerIdentifiedNull.new
            n.ber_identifier = id
            n
          else
            Net::BER.error("unsupported object type: id=#{id}")
          end
    obj
  end
  private :parse_ber_object

  #--
  # TODO: clean this up so it works properly with partial packets coming
  # from streams that don't block when we ask for more data (like
  # StringIOs). At it is, this can throw TypeErrors and other nasties.
  #
  # BEWARE, this violates DRY and is largely equal in functionality to
  # read_ber_from_string. Eventually that method may subsume the
  # functionality of this one.
  #++
  def read_ber(syntax = nil)
    # Don't trash this value, we'll use it later.
    id = getbyte or return nil
    n = getbyte

    lengthlength, contentlength = if n <= 127
                                   [1, n]
                                 else
                                   j = 0
                                   read(n & 127).each_byte { |n1|
                                     j = (j << 8) + n1
                                   }
                                   [1 + (n & 127), j]
                                 end

    newobj = read(contentlength)

    # This exceptionally clever and clear bit of code is verrrry slow.
    objtype = (syntax && syntax[id]) || BuiltinSyntax[id]

    parse_ber_object(id, objtype, syntax, newobj)
  end

  #--
  # Violates DRY! This replicates the functionality of #read_ber.
  # Eventually this method may replace that one.
  # This version of #read_ber behaves properly in the face of incomplete
  # data packets. If a full BER object is detected, we return an array containing
  # the detected object and the number of bytes consumed from the string.
  # If we don't detect a complete packet, return nil.
  #
  # Observe that weirdly we recursively call the original #read_ber in here.
  # That needs to be fixed if we ever obsolete the original method in favor of this one.
  def read_ber_from_string(str, syntax = nil)
    id = str[0] || return
    id = id.ord if RUBY_VERSION.to_f >= 1.9

    n = str[1] || return
    n = n.ord if RUBY_VERSION.to_f >= 1.9

    n_consumed = 2
    lengthlength,contentlength = if n <= 127
                                   [1,n]
                                 else
                                   n1 = n & 127
                                   return nil unless str.length >= (n_consumed + n1)
                                   j = 0
                                   n1.times do
                                     j = (j << 8) + str[n_consumed]
                                     n_consumed += 1
                                   end
                                   [1 + (n1), j]
                                 end

    return nil unless str.length >= (n_consumed + contentlength)
    newobj = str[n_consumed...(n_consumed + contentlength)]
    n_consumed += contentlength

    objtype = (syntax && syntax[id]) || BuiltinSyntax[id]

    # == is expensive so sort this if/else so the common cases are at the top.
    obj = if objtype == :array
            seq = Net::BER::BerIdentifiedArray.new
            seq.ber_identifier = id
            sio = StringIO.new(newobj || "")
            # Interpret the subobject, but note how the loop
            # is built: nil ends the loop, but false (a valid
            # BER value) does not!
            # Also, we can use the standard read_ber method because
            # we know for sure we have enough data. (Although this
            # might be faster than the standard method.)
            while (e = sio.read_ber(syntax)) != nil
              seq << e
            end
            seq
          elsif objtype == :string
            s = Net::BER::BerIdentifiedString.new(newobj || "")
            s.ber_identifier = id
            s
          elsif objtype == :integer
            j = 0
            newobj.each_byte {|b| j = (j << 8) + b}
            j
          elsif objtype == :oid
            # cf X.690 pgh 8.19 for an explanation of this algorithm.
            # Potentially not good enough. We may need a BerIdentifiedOid
            # as a subclass of BerIdentifiedArray, to get the ber identifier
            # and also a to_s method that produces the familiar dotted notation.
            oid = newobj.unpack("w*")
            f = oid.shift
            g = if f < 40
                  [0,f]
                elsif f < 80
                  [1, f-40]
                else
                  [2, f-80] # f-80 can easily be > 80. What a weird optimization.
                end
            oid.unshift g.last
            oid.unshift g.first
            oid
          elsif objtype == :boolean
            newobj != "\000"
          elsif objtype == :null
            n = Net::BER::BerIdentifiedNull.new
            n.ber_identifier = id
            n
          else
            raise BerError.new("unsupported object type: id=#{id}")
          end

    [obj, n_consumed]
  end
end
