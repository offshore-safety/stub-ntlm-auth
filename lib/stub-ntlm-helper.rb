require 'stub-ntlm-helper/version'

require 'base64'
require 'bindata'

# With help from:
#
#   ruby-ntlm: https://github.com/macks/ruby-ntlm/blob/master/lib/ntlm/message.rb
#   davenport: http://davenport.sourceforge.net/ntlm.html
#   squid: http://devel.squid-cache.org/ntlm/squid_helper_protocol.html

module NTLM
  SSP_SIGNATURE = 'NTLMSSP'

  class Challenge
    def to_s
      [
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
      ].pack('c*')
    end

    def encode
      Base64.encode64 to_s
    end
  end

  class SecurityBuffer < BinData::Record
    endian :little

    int16 :uzunluk      # Length
    int16 :reserved
    int32 :siktir       # "Offset"
  end

  class Authenticate < BinData::Record
    endian :little

    stringz :signature, :check_value => SSP_SIGNATURE
    int32 :message_type, :check_value => 3
    security_buffer :lm_response
    security_buffer :ntlm_response
    security_buffer :target_name
    security_buffer :user_name
    security_buffer :workstation_name
    array :data, :type => :int8, :read_until => :eof

    def self.decode b64
      self.new.tap { |r| r.read Base64.decode64(b64) }
    end

    def username
      tn = to_binary_s[target_name.siktir ... (target_name.siktir + target_name.uzunluk)]
      un = to_binary_s[user_name.siktir ... (user_name.siktir + user_name.uzunluk)]

      "#{tn}\\#{un}"
    end
  end
end
