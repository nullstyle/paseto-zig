# frozen_string_literal: true

# Generates cross-implementation interop fixtures for the Zig test suite by
# signing/encrypting fixed payloads with the vendored ruby-paseto reference.
#
# Regeneration is manual and local (see tests/vectors-interop/PROVENANCE.md):
#
#   cd tools/interop && bundle install
#   mise x ruby@3.4 -- bundle exec ruby generate.rb
#
# CI never runs this script; it only consumes the committed JSON.
# Keys, nonces, and payloads are fixed so v4 output is byte-stable.
# v3.public ECDSA signatures are randomized by OpenSSL per run: the recorded
# tokens remain valid, but regenerating changes those signature bytes.

require 'json'
require 'fileutils'
require 'singleton'
require 'rbnacl'

require 'paseto'

REPO_ROOT = File.expand_path('../..', __dir__)
OUT_PATH = File.join(REPO_ROOT, 'tests', 'vectors-interop', 'ruby-paseto.json')

# Fixed key material (test-only; public in the committed fixtures).
V4_LOCAL_KEY = 'interop-v4-local-key-0123456789a'
V4_SIGN_SEED = 'interop-v4-sign-seed-0123456789a'
V3_LOCAL_KEY = 'interop-v3-local-key-0123456789a'
V3_SCALAR = 'interop-v3-scalar-0123456789abcdefghijklmnopqrst'

raise 'v4 local key must be 32 bytes' unless V4_LOCAL_KEY.bytesize == 32
raise 'v4 seed must be 32 bytes' unless V4_SIGN_SEED.bytesize == 32
raise 'v3 local key must be 32 bytes' unless V3_LOCAL_KEY.bytesize == 32
raise 'v3 scalar must be 48 bytes' unless V3_SCALAR.bytesize == 48

V4_NONCE = (0...32).map { |i| ((i * 7 + 1) & 0xff).chr }.join
V3_NONCE = (0...32).map { |i| ((i * 5 + 3) & 0xff).chr }.join

PAYLOADS = [
  ['plain', 'interop smoke payload'],
  ['json', '{"sub":"interop","iss":"ruby-paseto","exp":"2035-01-01T00:00:00Z"}'],
  ['empty', ''],
  # ASCII-only: the reference's PAE concat mangles multibyte strings (its
  # v3 path raises Encoding::CompatibilityError outright, and its v4.public
  # signatures over UTF-8 messages do not verify against the spec PAE).
  # Recorded in tests/vectors-interop/PROVENANCE.md.
].freeze

def payloads_for(_version)
  PAYLOADS
end

def hex(str)
  str.unpack1('H*')
end

def local_cases(version, key, nonce)
  sk = version == 'v4' ? Paseto::V4::Local.new(ikm: key) : Paseto::V3::Local.new(ikm: key)
  payloads_for(version).flat_map do |label, payload|
    [
      { footer: '', implicit_assertion: '' },
      { footer: '{"kid":"interop"}', implicit_assertion: '' },
      { footer: '', implicit_assertion: 'interop:v1' },
      { footer: '{"kid":"interop"}', implicit_assertion: 'interop:v1' },
    ].each_with_index.map do |opts, i|
      token = sk.encrypt(message: payload, n: nonce, **opts)
      {
        'name' => "#{version}-local-#{label}-#{i}",
        'version' => version,
        'purpose' => 'local',
        'key_hex' => hex(key),
        'paserk' => sk.paserk,
        'lid' => sk.lid,
        'token' => token.to_s,
        'plaintext' => payload,
        'footer' => opts[:footer],
        'implicit_assertion' => opts[:implicit_assertion],
      }
    end
  end
end

def v4_public_cases
  signing = Paseto::V4::Public.new(RbNaCl::SigningKey.new(V4_SIGN_SEED))
  verifier = Paseto::V4::Public.from_public_bytes(signing.public_bytes)
  payloads_for('v4').flat_map do |label, payload|
    [
      { footer: '', implicit_assertion: '' },
      { footer: '{"kid":"interop"}', implicit_assertion: 'interop:v1' },
    ].each_with_index.map do |opts, i|
      token = signing.sign(message: payload, **opts)
      {
        'name' => "v4-public-#{label}-#{i}",
        'version' => 'v4',
        'purpose' => 'public',
        'seed_hex' => hex(V4_SIGN_SEED),
        'public_hex' => hex(verifier.public_bytes),
        'paserk' => signing.paserk,
        'public_paserk' => signing.public_paserk,
        'sid' => signing.id,
        'pid' => signing.pid,
        'token' => token.to_s,
        'plaintext' => payload,
        'footer' => opts[:footer],
        'implicit_assertion' => opts[:implicit_assertion],
      }
    end
  end
end

def v3_public_cases
  signing = Paseto::V3::Public.from_scalar_bytes(V3_SCALAR)
  verifier = Paseto::V3::Public.from_public_bytes(signing.public_bytes)
  payloads_for('v3').flat_map do |label, payload|
    [
      { footer: '', implicit_assertion: '' },
      { footer: '{"kid":"interop"}', implicit_assertion: 'interop:v1' },
    ].each_with_index.map do |opts, i|
      token = signing.sign(message: payload, **opts)
      {
        'name' => "v3-public-#{label}-#{i}",
        'version' => 'v3',
        'purpose' => 'public',
        'scalar_hex' => hex(V3_SCALAR),
        'public_hex' => hex(verifier.public_bytes),
        'paserk' => signing.paserk,
        'public_paserk' => signing.public_paserk,
        'sid' => signing.id,
        'pid' => signing.pid,
        'token' => token.to_s,
        'plaintext' => payload,
        'footer' => opts[:footer],
        'implicit_assertion' => opts[:implicit_assertion],
      }
    end
  end
end

cases = [
  *local_cases('v4', V4_LOCAL_KEY, V4_NONCE),
  *v4_public_cases,
  *local_cases('v3', V3_LOCAL_KEY, V3_NONCE),
  *v3_public_cases,
]

doc = {
  'generator' => {
    'implementation' => 'ruby-paseto (vendored at vendor/ruby)',
    'version' => Paseto::VERSION,
    'ruby' => RUBY_VERSION,
  },
  'cases' => cases,
}

FileUtils.mkdir_p(File.dirname(OUT_PATH))
File.write(OUT_PATH, JSON.pretty_generate(doc) + "\n")
puts "wrote #{OUT_PATH} (#{cases.size} cases)"
