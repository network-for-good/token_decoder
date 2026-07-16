module TokenDecoder
  class Decoder
    # Passing 'true' to the public_key method will attempt to decode the token
    # against a secondary cert if one exists.

    require "jwt"

    class << self
      attr_accessor :environment, :hmac_secret

      def decode(token, environment)
        self.environment = environment
        options = { algorithm: 'RS256' }

        begin
          # first decode using the primary key
          JWT.decode(token, public_key, true, options)
        rescue StandardError
          begin
            # then decode using the secondary key
            JWT.decode(token, public_key(true), true, options)
          rescue StandardError
            # now attempt to decode using the hmac_secret. Do not fall back to an
            # empty string when hmac_secret is unset: CVE-2026-45363 (GHSA-c32j-vqhx-rx3x)
            # is an empty-key HMAC verification bypass, and JWT.decode(token, '', ...)
            # is exactly that condition on JWT gems affected by it. An unset hmac_secret
            # means this app does not use the HMAC path (see config/initializers in
            # consuming apps), so fail closed instead of silently trying one.
            raise JWT::DecodeError, "hmac_secret is not configured" if hmac_secret.nil? || hmac_secret.empty?

            JWT.decode(token, hmac_secret, true, algorithm: 'HS256')
          end
        end
      end

      def public_key(use_secondary_cert = false)
        certificate(use_secondary_cert).public_key
      end

      def cert_file_path(use_secondary_cert = false)
        File.join(__dir__, 'public_key_certs', cert_file_name(use_secondary_cert))
      end

      def cert_file_name(use_secondary_cert = false)
        secondary_name = use_secondary_cert ? "_secondary" : ""
        case environment
        when 'test', 'qa', 'development'
          "nfg_qa#{secondary_name}.cer"
        else
          "nfg_production#{secondary_name}.cer"
        end
      end

      def certificate(use_secondary_cert = false)
        OpenSSL::X509::Certificate.new(File.read(cert_file_path(use_secondary_cert)))
      end
    end
  end
end

