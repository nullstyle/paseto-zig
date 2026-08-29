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

# SymmetricKey exposes the raw key via #key; AsymmetricKey#key is the
# underlying OpenSSL/RbNaCl object, while #to_bytes is the PASERK wire form
# (v4 seed / v3 scalar) that wrapping operations encrypt.
def key_bytes(key)
  key.is_a?(Paseto::SymmetricKey) ? key.key : key.to_bytes
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
        'op' => 'token',
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
        'op' => 'token',
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
        'op' => 'token',
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


V4_PIE_NONCE = (0...32).map { |i| ((i * 3 + 5) & 0xff).chr }.join
V3_PIE_NONCE = (0...32).map { |i| ((i * 3 + 5) & 0xff).chr }.join
PBKW_PASSWORD = 'interop pbkw password 01'

# PIE: deterministic nonce makes v4 output byte-stable across regenerations.
def pie_cases(version, wrapping_key, victims, nonce)
  victims.filter_map do |label, victim_key|
    next unless victim_key
    wrapped = Paseto::Paserk.wrap(key: victim_key, wrapping_key: wrapping_key, nonce: nonce)
    {
      'name' => "#{version}-pie-#{label}",
      'op' => 'pie',
      'version' => version,
      'wrapping_key_hex' => hex(wrapping_key.key),
      'paserk' => wrapped,
      'unwrapped_kind' => label,
      'victim_hex' => hex(key_bytes(victim_key)),
    }
  end
end

# PKE: ephemeral keys are random per run; recorded values stay valid.
# recipient_hex is the unsealing key in wire form: v4 seed (32) or v3
# scalar (48).
def pke_cases(version, _recipient, recipient_hex, victim_key, victim_label)
  sealed = _recipient.seal(victim_key)
  [{
    'name' => "#{version}-pke-#{victim_label}",
    'op' => 'pke',
    'version' => version,
    'recipient_hex' => recipient_hex,
    'paserk' => sealed,
    'unwrapped_kind' => victim_label,
    'victim_hex' => hex(key_bytes(victim_key)),
  }]
end

# PBKW: salt and nonce are random per run; recorded values stay valid.
# Parameters sit inside paseto-zig's production policy envelope so the Zig
# side unwraps with the default (production) policy in CI.
def pbkw_cases
  v4_local = Paseto::V4::Local.new(ikm: V4_LOCAL_KEY)
  v4_secret = Paseto::V4::Public.new(RbNaCl::SigningKey.new(V4_SIGN_SEED))
  v3_local = Paseto::V3::Local.new(ikm: V3_LOCAL_KEY)

  [
    ['v4-pbwk-local', 'v4', v4_local, 'local', { memlimit: 67_108_864, opslimit: 2 }],
    ['v4-pbwk-secret', 'v4', v4_secret, 'secret', { memlimit: 67_108_864, opslimit: 2 }],
    ['v3-pbwk-local', 'v3', v3_local, 'local', { iterations: 10_000 }],
  ].map do |name, version, key, kind, params|
    wrapped = Paseto::Paserk.pbkw(key: key, password: PBKW_PASSWORD, options: params)
    {
      'name' => name,
      'op' => 'pbkw',
      'version' => version,
      'password' => PBKW_PASSWORD,
      'paserk' => wrapped,
      'unwrapped_kind' => kind,
      'victim_hex' => hex(key_bytes(key)),
    }
  end
end

v4_wrapping = Paseto::V4::Local.new(ikm: V4_LOCAL_KEY)
v3_wrapping = Paseto::V3::Local.new(ikm: V3_LOCAL_KEY)
v4_secret_victim = Paseto::V4::Public.new(RbNaCl::SigningKey.new(V4_SIGN_SEED))
v3_secret_victim = Paseto::V3::Public.from_scalar_bytes(V3_SCALAR)
v4_local_victim = Paseto::V4::Local.new(ikm: V4_LOCAL_KEY)
v3_local_victim = Paseto::V3::Local.new(ikm: V3_LOCAL_KEY)

cases = [
  *local_cases('v4', V4_LOCAL_KEY, V4_NONCE),
  *v4_public_cases,
  *local_cases('v3', V3_LOCAL_KEY, V3_NONCE),
  *v3_public_cases,
  *pie_cases('v4', v4_wrapping, [['local', v4_local_victim], ['secret', v4_secret_victim]], V4_PIE_NONCE),
  *pie_cases('v3', v3_wrapping, [['local', v3_local_victim], ['secret', v3_secret_victim]], V3_PIE_NONCE),
  *pke_cases('v4', Paseto::V4::Public.from_public_bytes(v4_secret_victim.public_bytes), hex(V4_SIGN_SEED), v4_local_victim, 'local'),
  *pke_cases('v3', Paseto::V3::Public.from_public_bytes(v3_secret_victim.public_bytes), hex(V3_SCALAR), v3_local_victim, 'local'),
  *pbkw_cases,
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
