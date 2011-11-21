require 'stub-ntlm-helper/version'

require 'base64'
require 'bindata'
require 'iconv'

# With help from:
#
#   ruby-ntlm: https://github.com/macks/ruby-ntlm/blob/master/lib/ntlm/message.rb
#   davenport: http://davenport.sourceforge.net/ntlm.html
#   squid: http://devel.squid-cache.org/ntlm/squid_helper_protocol.html

module NTLM
  SSP_SIGNATURE = 'NTLMSSP'

  class Challenge
    def to_s
      # Stolen example from davenport docs.
      [
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
      ].pack('c*')
    end

    def encode
      # We don't work because we're NTLMv1. We need to advertise NTLMv2.
      # Base64.encode64(to_s)
      
      # I stole this from a curl request. Only works on "rms-prototype"
      'TlRMTVNTUAACAAAACAAIADAAAAAFgokADOSQDeBSFP4AAAAAAAAAAI4AjgA4AAAAQwBPAFIAUAACAAgAQwBPAFIAUAABABYATgBPAFAARABFAFYAQQBQAFAAMAA1AAQAIgBjAG8AcgBwAC4AbgBvAHAAcwBhAC4AZwBvAHYALgBhAHUAAwA6AG4AbwBwAGQAZQB2AGEAcABwADAANQAuAGMAbwByAHAALgBuAG8AcABzAGEALgBnAG8AdgAuAGEAdQAAAAAA'
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
      # Since we're parroting a sketchy packet, we support both OEM and Unicode
      # strings.  Except, we don't, because Ruby 1.8 blows. Here I use the
      # dumbest heuristic ever to figure out if we're ucs-2le and thus need to
      # be utf-8. (Though, really, we probably need to be ASCII.)
      #
      # If we aren't utf-8/ASCII, then Apache chokes.

      tn = to_binary_s[target_name.siktir ... (target_name.siktir + target_name.uzunluk)]
      tn = Iconv.conv('utf-8', 'ucs-2le', tn) if tn["\0"]

      un = to_binary_s[user_name.siktir ... (user_name.siktir + user_name.uzunluk)]
      un = Iconv.conv('utf-8', 'ucs-2le', un) if un["\0"]

      "#{tn}+#{un}"
    end
  end
end
