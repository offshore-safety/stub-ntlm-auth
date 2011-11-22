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

  module Serializer
    module ClassMethods
      def decode b64
        self.new.tap { |r| r.read Base64.decode64(b64) }
      end
    end

    def self.included klass
      klass.extend ClassMethods
    end

    def encode
      Base64.encode64(to_binary_s).tr "\n", ""
    end
  end

  class SecurityBuffer < BinData::Record
    endian :little

    int16 :uzunluk      # Length
    int16 :reserved
    int32 :siktir       # "Offset"

    def value
      parent.to_binary_s[siktir ... (siktir + uzunluk)]
    end
  end

  class Flags < BinData::Record
    # D
    bit1 :negotiate_lm_key            # LAN Manager session key computation
    bit1 :negotiate_datagram          # Connectionless authentication
    bit1 :negotiate_seal              # Session key negotiation for message confidentiality
    bit1 :negotiate_sign              # Session key negotiation for message signatures
    bit1 :unused10
    bit1 :request_target              # TargetName is supplied in challenge message
    bit1 :negotiate_oem               # OEM character set encoding
    bit1 :negotiate_unicode           # Unicode character set encoding

    # C
    bit1 :negotiate_always_sign
    bit1 :unused7
    bit1 :oem_workstation_supplied    # Workstations field is present
    bit1 :oem_domain_supplied         # Domain field is present
    bit1 :anonymous                   # Anonymous connection
    bit1 :unused8
    bit1 :negotiate_ntlm              # NTLM v1 protocol
    bit1 :unused9

    # B
    bit1 :negotiate_target_info       # Requests TargetInfo
    bit1 :request_non_nt_session_key  # LM session key is used
    bit1 :unused5
    bit1 :negotiate_identify          # Requests identify level token
    bit1 :negotiate_extended_security # NTLM v2 session security
    bit1 :unused6
    bit1 :target_type_server          # TargetName is server name
    bit1 :target_type_domain          # TargetName is domain name

    # A
    bit1 :negotiate_56                # 56bit encryption
    bit1 :negotiate_key_exch          # Explicit key exchange
    bit1 :negotiate_128               # 128bit encryption
    bit1 :unused1
    bit1 :unused2
    bit1 :unused3
    bit1 :negotiate_version           # Version field is present
    bit1 :unused4
  end

  class Challenge < BinData::Record
    include Serializer

    endian :little

    stringz :signature, :value => SSP_SIGNATURE, :check_value => SSP_SIGNATURE
    int32 :message_type, :value => 2, :check_value => 2
    security_buffer :target_name
    flags :flags
    string :challenge, :length => 8
    array :data, :type => :int8, :read_until => :eof
  end

  class Authenticate < BinData::Record
    include Serializer

    endian :little

    stringz :signature, :check_value => SSP_SIGNATURE
    int32 :message_type, :check_value => 3
    security_buffer :lm_response
    security_buffer :ntlm_response
    security_buffer :target_name
    security_buffer :user_name
    security_buffer :workstation_name
    array :data, :type => :int8, :read_until => :eof

    def username
      "#{target_name.value}+#{user_name.value}"
    end
  end
end
