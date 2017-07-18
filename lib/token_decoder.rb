require "token_decoder/version"

module TokenDecoder
  class Decoder
    # Passing 'true' to the public_key method will attempt to decode the token
    # against a secondary cert if one exists.

    require "jwt"

    class << self
      attr_accessor :environment

      def decode(token, environment)
        self.environment = environment
        options = { algorithm: 'RS256' }

        begin
          JWT.decode(token, public_key, true, options)
        rescue
          JWT.decode(token, public_key(true), true, options)
        end
      end

      def public_key(use_secondary_cert = false)
        certificate(use_secondary_cert).public_key
      end

      def cert_file_path(use_secondary_cert = false)
        File.join(__dir__, 'token_decoder', 'public_key_certs', cert_file_name(use_secondary_cert))
      end

      def cert_file_name(use_secondary_cert = false)
        secondary_name = use_secondary_cert ? "_secondary" : ""
        case self.environment
        when 'test', 'qa', 'development'
          "nfg_qa#{ secondary_name }.cer"
        else
          "nfg_production#{ secondary_name }.cer"
        end
      end

      def certificate(use_secondary_cert = false)
        OpenSSL::X509::Certificate.new(File.read(cert_file_path(use_secondary_cert)))
      end
    end

  end
end
