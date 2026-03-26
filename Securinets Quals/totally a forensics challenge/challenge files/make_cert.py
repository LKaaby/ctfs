from OpenSSL import crypto

# Load private key
with open("server.key", "rb") as f:
    key_data = f.read()

pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

# Create certificate
cert = crypto.X509()
cert.get_subject().CN = "e-corp"
cert.set_serial_number(1)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(pkey)
cert.sign(pkey, "sha256")

# Write certificate
with open("server.crt", "wb") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

print("Generated server.crt")
