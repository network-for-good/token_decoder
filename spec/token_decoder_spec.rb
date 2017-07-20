require 'spec_helper'
require 'yaml'

describe TokenDecoder::Decoder do
  let(:tokens) { YAML.load_file(File.join('spec', 'fixtures', 'api_keys.yml')) }
  let(:decoder_class) { TokenDecoder::Decoder }
  let(:decoder) { decoder_class.decode(token, environment) }
  let(:token) { tokens['production']['primary'] }
  let!(:public_key) { certificate.public_key }
  let(:cert_file_path) { File.join(Gem::Specification.find_by_name("token_decoder").gem_dir, 'lib', 'token_decoder', 'public_key_certs', file_name) }
  let(:certificate) { OpenSSL::X509::Certificate.new(File.read(cert_file_path)) }
  let(:file_name) { 'nfg_production.cer' }

  describe ".certificate" do
    subject { decoder_class.certificate }

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
      subject { decoder_class.certificate(true) }

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
      subject { decoder_class.public_key }

      it "should return the public key associated with the current environment" do
        expect(certificate).to receive(:public_key).and_return(public_key)
        expect(decoder_class).to receive(:certificate).and_return(certificate)
        expect(subject).to eq(public_key)
      end
    end

    context "when using the secondary certificate" do
      subject { decoder_class.public_key(true) }

      it "should return the public key associated with the current environment" do
        expect(certificate).to receive(:public_key).and_return(public_key)
        expect(decoder_class).to receive(:certificate).with(true).and_return(certificate)
        expect(subject).to eq(public_key)
      end
    end
  end

  describe ".decode" do
    let(:decoded_token) { JWT.decode(token, public_key, true, { algorithm: "RS256" }) }

    describe "in qa" do
      let(:environment) { "qa" }

      context "when the token was generated from a primary certificate" do
        let!(:token) { tokens['qa']['primary'] }
        let(:file_name) { 'nfg_qa.cer' }
        subject { decoder_class.decode(token, environment) }

        it { should eq decoded_token }
      end

      context "when the token was generated from a secondary certificate" do
        let!(:token) { tokens['qa']['secondary'] }
        let(:file_name) { 'nfg_qa_secondary.cer' }
        subject { decoder_class.decode(token, environment) }

        it { should eq decoded_token }
      end
    end

    describe "in production" do
      let(:environment) { "production" }

      context 'when the token was generated from the primary certificate' do
        let!(:token) { tokens['production']['primary'] }
        let(:file_name) { 'nfg_production.cer' }
        subject { decoder_class.decode(token, environment) }

        it { should eq decoded_token }
      end

      context 'when the token was generated from the secondary certificate' do
        let!(:token) { tokens['production']['secondary'] }
        let(:file_name) { 'nfg_production_secondary.cer' }
        subject { decoder_class.decode(token, environment) }

        it { should eq decoded_token }
      end
    end
  end
end