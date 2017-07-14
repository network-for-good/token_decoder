# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "token_decoder/version"

Gem::Specification.new do |spec|
  spec.name          = "token_decoder"
  spec.version       = TokenDecoder::VERSION
  spec.authors       = ["Timothy King"]
  spec.email         = ["timothy.king@networkforgood.com"]

  spec.summary       = %q{A token decoder class used by the sso authentication and admin manager gems}
  spec.homepage      = "https://github/networkforgood/token_decoder"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt"

  spec.add_development_dependency "bundler", "~> 1.15"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
