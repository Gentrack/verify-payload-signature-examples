require 'openssl'

def verify_signature(x_payload_signature, public_key, payload)
  parts = x_payload_signature.split(',')
  timestamp = parts[0].split('=')[1]
  sig_to_verify = parts[1].split('=')[1]
  v = "#{timestamp}.#{payload}"
  data = v.encode('utf-8')
  signature = Base64.decode64(sig_to_verify)
  rsa_public_key = OpenSSL::PKey::RSA.new(public_key)
  rsa_public_key.verify(OpenSSL::Digest::SHA512.new, signature, data)
end

x_payload_signature = "t=1234567890,v=abcdefg"
public_key = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEpFwIarbm48m6ueG+jhpt2vCGaqXZlwR/HPuL4zH1DQ/eWFbgQtVnrta8QhQz3ywLnbX6s7aecxUzzNJsTtS8VxKAYll4E1lJUqrNdWt8CU+TaUQuFm8vzLoPiYKEXl4bX5rzMQUMqA228gWuYmRFQnpduQTgnYIMO8XVUQXl5wIDAQAB\n-----END PUBLIC KEY-----"
payload = "some_payload"

result = verify_signature(x_payload_signature, public_key, payload)
puts result
