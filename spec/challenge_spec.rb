require 'stub-ntlm-helper'

describe NTLM::Challenge do
  context "a minimal type 2 message" do
    let(:minimal_type_2_message) { 'TlRMTVNTUAACAAAAAAAAAAAAAAACAgAAASNFZ4mrze8=' }

    subject { NTLM::Challenge.decode minimal_type_2_message }

    [:negotiate_ntlm, :negotiate_oem].each do |f|
      it "#{f} flag should be true" do
        subject.flags[f].should == 1
      end
    end

    [
      :negotiate_lm_key, :negotiate_datagram, :negotiate_seal,
      :negotiate_sign, :unused10, :request_target, :negotiate_unicode,
      :negotiate_always_sign, :unused7, :oem_workstation_supplied,
      :oem_domain_supplied, :anonymous, :unused8, :unused9,
      :negotiate_target_info, :request_non_nt_session_key, :unused5,
      :negotiate_identify, :negotiate_extended_security, :unused6,
      :target_type_server, :target_type_domain, :negotiate_56,
      :negotiate_key_exch, :negotiate_128, :unused1, :unused2, :unused3,
      :negotiate_version, :unused4
    ].each do |f|
      it "#{f} flag should be false" do
        subject.flags[f].should == 0
      end
    end
  end
end
