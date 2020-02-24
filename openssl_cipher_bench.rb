# frozen_string_literal: true

require 'benchmark'
require 'openssl'
require 'base64'

STRING_TO_ENCRYPT = '326415'
INITIALIZATION_VECTOR = '0000000000000000'
ENCRYPTION_KEY = Digest::MD5.hexdigest 'absessive'
TIMES_RUN = 1_000_000
AES_256_CBC = {
  encryption_key: ENCRYPTION_KEY,
  iv: INITIALIZATION_VECTOR
}
AES_128_CBC = {
  encryption_key: ENCRYPTION_KEY[0...16],
  iv: INITIALIZATION_VECTOR
}
AES_128_CTR = {
  encryption_key: ENCRYPTION_KEY[0...16],
  iv: INITIALIZATION_VECTOR
}
AES_256_CTR = {
  encryption_key: ENCRYPTION_KEY,
  iv: INITIALIZATION_VECTOR
}
# Blowfish is quite slow, so skipping this in the benchmarks
BF = {
  encryption_key: ENCRYPTION_KEY[0...16],
  iv: INITIALIZATION_VECTOR[0...8]
}

CHACHA20 = {
  encryption_key: ENCRYPTION_KEY,
  iv: INITIALIZATION_VECTOR
}

ALGORITHMS = {
  "aes-256-cbc" => AES_256_CBC,
  "aes-128-cbc" => AES_128_CBC,
  "aes-128-ctr" => AES_128_CTR,
  "aes-256-ctr" => AES_256_CTR,
  "chacha20" => CHACHA20
}

Benchmark.bm do |benchmark|
  ALGORITHMS.each do |key, value|
    benchmark.report(key) do
      TIMES_RUN.times do
        @cipher = OpenSSL::Cipher.new(key)
        @cipher.encrypt
        @cipher.key = value[:encryption_key]
        @cipher.iv = value[:iv] unless (key == 'bf-ecb' || key == 'aes-256-ctr')
        result = @cipher.update(STRING_TO_ENCRYPT)
        result << @cipher.final
        encrypted_value = Base64.urlsafe_encode64 result
        encrypted_value
      end
    end
  end
end
