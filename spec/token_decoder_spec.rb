require 'spec_helper'
require 'yaml'

describe TokenDecoder::Decoder do
  let(:tokens) { YAML.load_file(File.join('spec', 'fixtures', 'api_keys.yml')) }
  let(:decoder) { described_class.decode(token, environment) }
  let(:token) { tokens['production']['primary'] }
  let!(:public_key) { certificate.public_key }
  let(:cert_file_path) { File.join(Gem::Specification.find_by_name("token_decoder").gem_dir, 'lib', 'token_decoder', 'public_key_certs', file_name) }
  let(:certificate) { OpenSSL::X509::Certificate.new(File.read(cert_file_path)) }
  let(:file_name) { 'nfg_production.cer' }
  
  describe ".certificate" do
    subject { described_class.certificate }

    before { allow(TokenDecoder::Decoder).to receive(:environment).and_return(environment) }

    describe 'when using the primary certificate' do
      context "in development" do
        let(:environment) { "development" }
        let(:file_name) { 'nfg_qa.cer' }

        it "should return the OpenSSL version of the qa cert" do
          cert_file = File.read(cert_file_path)
          expect(File).to receive(:read).with(cert_file_path).and_return(cert_file)
          expect(OpenSSL::X509::Certificate).to receive(:new).with(cert_file)
          subject
        end
      end

      context "when running in production" do
        let(:environment) { "production" }
        let(:file_name) { 'nfg_production.cer' }

        it "should return the OpenSSL version of the production cert" do
          cert_file = File.read(cert_file_path)
          expect(File).to receive(:read).with(cert_file_path).and_return(cert_file)
          expect(OpenSSL::X509::Certificate).to receive(:new).with(cert_file)
          subject
        end
      end
    end

    describe "when using the secondary certificate" do
      subject { described_class.certificate(true) }

      context "in development" do
        let(:environment) { "development" }
        let(:file_name) { 'nfg_qa_secondary.cer' }

        it "should return the OpenSSL version of the qa secondary cert" do
          cert_file = File.read(cert_file_path)
          expect(File).to receive(:read).with(cert_file_path).and_return(cert_file)
          expect(OpenSSL::X509::Certificate).to receive(:new).with(cert_file)
          subject
        end
      end

      context "in production" do
        let(:environment) { "production" }
        let(:file_name) { 'nfg_production_secondary.cer' }

        it "should return the OpenSSL version of the production cert" do
          cert_file = File.read(cert_file_path)
          expect(File).to receive(:read).with(cert_file_path).and_return(cert_file)
          expect(OpenSSL::X509::Certificate).to receive(:new).with(cert_file)
          subject
        end
      end
    end
  end

  describe ".public_key" do
    let(:environment) { "production" }

    before { allow(TokenDecoder::Decoder).to receive(:environment).and_return(environment) }

    context "when using the primary certificate" do
      subject { described_class.public_key }

      it "should return the public key associated with the current environment" do
        expect(certificate).to receive(:public_key).and_return(public_key)
        expect(described_class).to receive(:certificate).and_return(certificate)
        expect(subject).to eq(public_key)
      end
    end

    context "when using the secondary certificate" do
      subject { described_class.public_key(true) }

      it "should return the public key associated with the current environment" do
        expect(certificate).to receive(:public_key).and_return(public_key)
        expect(described_class).to receive(:certificate).with(true).and_return(certificate)
        expect(subject).to eq(public_key)
      end
    end
  end

  describe ".decode" do
    #let(:decoded_token) { JWT.decode(token, public_key, true, { algorithm: "RS256" }) }

    context "when decoding succeeds" do
      let(:decoded_token) { "XYZ" }

      before { allow(JWT).to receive(:decode).and_return(decoded_token) }
      
      describe "in qa" do
        let(:environment) { "qa" }
        
        # it { byebug }
        context "when the token was generated from a primary certificate" do
          let!(:token) { tokens['qa']['primary'] }
          let(:file_name) { 'nfg_qa.cer' }
          subject { described_class.decode(token, environment) }

          it { should eq decoded_token }
        end

        context "when the token was generated from a secondary certificate" do
          let!(:token) { tokens['qa']['secondary'] }
          let(:file_name) { 'nfg_qa_secondary.cer' }
          subject { described_class.decode(token, environment) }

          it { should eq decoded_token }
        end
      end

      describe "in production" do
        let(:environment) { "production" }

        context 'when the token was generated from the primary certificate' do
          let!(:token) { tokens['production']['primary'] }
          let(:file_name) { 'nfg_production.cer' }
          subject { described_class.decode(token, environment) }

          it { should eq decoded_token }
        end

        context 'when the token was generated from the secondary certificate' do
          let!(:token) { tokens['production']['secondary'] }
          let(:file_name) { 'nfg_production_secondary.cer' }
          subject { described_class.decode(token, environment) }

          it { should eq decoded_token }
        end
      end
    end

    context "when decoding fails" do
      context "when passed an invalid token" do
        let(:token) { "invalidtokenKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1RdjVzaDZ6ZElvb3l2eHFER2M1c2dOVWdUUSIsImtpZCI6Ik1RdjVzaDZ6ZElvb3l2eHFER2M1c2dOVWdUUSJ9.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LXFhMDUubmZnaHEub3JnIiwiYXVkIjoiaHR0cHM6Ly9pZGVudGl0eS1xYTA1Lm5mZ2hxLm9yZy9yZXNvdXJjZXMiLCJleHAiOjE2MzQ1OTgwNDksIm5iZiI6MTQ3NjgxMDA0OSwiY2xpZW50X2lkIjoiTmdmVDNzdGlEIiwiY2xpZW50X3BhcnRuZXJfaWQiOiIxMDA4NTMiLCJjbGllbnRfY2FwYWJpbGl0aWVzIjpbIjAiLCIxIiwiMiIsIjMiLCI0IiwiNiIsIjgiLCI5IiwiMTAiLCIxMSIsIjEyIiwiMTMiLCIxNCIsIjE1IiwiMTYiLCIxOCIsIjE5IiwiMjAiLCIyMSJdLCJjbGllbnRfY2FtcGFpZ25DYXBhYmlsaXRpZXMxMTU2NCI6WyIwIiwiMSIsIjUiLCI2IiwiNyIsIjgiLCI5Il0sImNsaWVudF9jYW1wYWlnbkNhcGFiaWxpdGllczEyNzQwIjpbIjAiLCIxIiwiNSIsIjYiLCI3IiwiOCIsIjkiLCIxMCJdLCJjbGllbnRfY2FtcGFpZ25DYXBhYmlsaXRpZXMxMjc0MiI6WyIwIiwiMSIsIjUiLCI2IiwiNyIsIjgiLCI5IiwiMTAiXSwiY2xpZW50X2NhbXBhaWduQ2FwYWJpbGl0aWVzMTI3MzgiOlsiMCIsIjEiLCI1IiwiNiIsIjciLCI4IiwiOSIsIjEwIl0sImNsaWVudF9jYW1wYWlnbkNhcGFiaWxpdGllczEyNzM2IjpbIjAiLCIxIiwiNSIsIjYiLCI3IiwiOCIsIjkiLCIxMCJdLCJjbGllbnRfY2FtcGFpZ25DYXBhYmlsaXRpZXMxMjc0MyI6WyIwIiwiMSIsIjUiLCI2IiwiNyIsIjgiLCI5IiwiMTAiXSwiY2xpZW50X2NhbXBhaWduQ2FwYWJpbGl0aWVzMTI3MzkiOlsiMCIsIjEiLCI1IiwiNiIsIjciLCI4IiwiOSIsIjEwIl0sImNsaWVudF9jYW1wYWlnbkNhcGFiaWxpdGllczEyNzM3IjpbIjAiLCIxIiwiNSIsIjYiLCI3IiwiOCIsIjkiLCIxMCJdLCJjbGllbnRfY2FtcGFpZ25DYXBhYmlsaXRpZXMxMjc0MSI6WyIwIiwiMSIsIjUiLCI2IiwiNyIsIjgiLCI5IiwiMTAiXSwiY2xpZW50X2NhbXBhaWduQ2FwYWJpbGl0aWVzMTI3MjMiOlsiMCIsIjEiLCI1IiwiNiIsIjciLCI4IiwiOSIsIjEwIl0sImNsaWVudF9jYW1wYWlnbkNhcGFiaWxpdGllczEyNzM1IjpbIjAiLCIxIiwiNSIsIjYiLCI3IiwiOCIsIjkiLCIxMCJdLCJjbGllbnRfY2FtcGFpZ25DYXBhYmlsaXRpZXMxMDQ5MSI6WyIwIiwiMSIsIjQiLCI1IiwiNiIsIjciLCI4IiwiOSJdLCJjbGllbnRfY2FtcGFpZ25DYXBhYmlsaXRpZXMxMTY2OSI6WyIwIiwiMSIsIjUiLCI2IiwiNyIsIjgiLCI5Il0sImNsaWVudF9jYW1wYWlnbkNhcGFiaWxpdGllczExNjUxIjpbIjAiLCIxIiwiNSIsIjYiLCI3IiwiOCIsIjkiXSwic2NvcGUiOlsiZG9uYXRpb24iLCJkb25hdGlvbi1yZXBvcnRpbmciLCJpZG1nciJdLCJqdGkiOiI3Y2NmNzBlOGZkNjY0NGE4ZGMxYWMwY2NiYzU4MDk0ZSJ9.i2fyyPJq_ko8HBJxChrH7upV4lDu1vAba6EToQvznoAaMwrJkoGdKp78LtyAxpKtZVItR8mEH97XcFmZxiTY9Vof3ShWFLtPjzzVyxM3pjNQuzzzEJTgA7Vm4-dGGue4cm4JMsqhuW6h_c8JAHISHnscjguTsx6wNldykLPAEFniUMLo_c_WF1GenRAM0xGiqjz3wmugJ7KFsrl4_8WW6-GzfEyMp5CRNjyeiUs9_aL5Z2qDfvIo0ewWf6Hr7Cz0CYZxHeWtbazx2nZU10UQuhi5LMwN-65NRrSAaQeuUlBZWVvrau5HYKcA5PbKEH_g4ME1Hy-WwZpahvTJQ7gpqA" }
        let(:environment) { "qa" }

        subject { described_class.decode(token, environment) }

        it 'raises an JWT::DecodeError error' do
          expect { subject }.to raise_error(JWT::DecodeError)
        end
      end
    end

    context "when passed a token that was created using an hmac_secret" do
      before do
        # containing applications use APP_CONFIG for injecting security
        # keys into the app
        # Here, we spoof that one
        described_class.hmac_secret = hmac_secret
      end

      let(:token) { JWT.encode({ app_id: 'evo' }, hmac_secret, 'HS256') }
      let(:decoded_token) { JWT.decode(token, hmac_secret, 'HS256') }
      let(:hmac_secret) { 'a2a06bd8c5750e77a884cd823e6a79a40ca24593c55a2c1bae0e521ec3bec10a9a837c101a8d7b3fb3c94a5954e1a2e68045c33890291888203b53f6f0b87474' }
      let(:environment) { "qa" }

      subject { described_class.decode(token, environment) }

      it "returns a decoded token" do
        described_class.hmac_secret = hmac_secret
        expect(subject).to eq(decoded_token)
      end
    end
  end
end
