import pyshark
import json

# Lookup table: cipher suite hex ID -> (readable name, risk level)
CIPHER_SUITE_INFO = {
    "0x1301": ("TLS_AES_128_GCM_SHA256", "strong"),
    "0x1302": ("TLS_AES_256_GCM_SHA384", "strong"),
    "0x1303": ("TLS_CHACHA20_POLY1305_SHA256", "strong"),
    "0xc02f": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "strong"),
    "0xc030": ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "strong"),
    "0x009c": ("TLS_RSA_WITH_AES_128_GCM_SHA256", "moderate"),
    "0x002f": ("TLS_RSA_WITH_AES_128_CBC_SHA", "weak"),
    "0x000a": ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "weak"),
    "0x0004": ("TLS_RSA_WITH_RC4_128_MD5", "critical"),
    "0x0005": ("TLS_RSA_WITH_RC4_128_SHA", "critical"),
}

# Known weak/deprecated signature algorithm OIDs
WEAK_SIG_ALGORITHMS = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
}

def lookup_cipher(hex_id):
    return CIPHER_SUITE_INFO.get(hex_id, ("UNKNOWN_CIPHER", "unknown"))


# Load the capture, filtering only your session's port
cap = pyshark.FileCapture("real_smtp_capture.pcapng", display_filter="tcp.port==2525")

# This will hold our final structured output
session_data = {
    "session_id": "sess_001_good",
    "protocol": "TLS-Test",
    "src_port": 4433,
    "sni": None,
    "tls_version_client": None,
    "tls_version_server": None,
    "cipher_suite_id": None,
    "cipher_suite_name": None,
    "cipher_risk": None,
    "signature_algorithm_oid": None,
    "signature_algorithm_name": None,
    "cert_common_name": None,
    "cert_risk": None
}

for pkt in cap:
    if hasattr(pkt, 'tls'):
        tls_layer = pkt.tls

        # Client Hello detection
        if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '1':
            if hasattr(tls_layer, 'handshake_version'):
                session_data["tls_version_client"] = tls_layer.handshake_version
            if hasattr(tls_layer, 'handshake_extensions_server_name'):
                session_data["sni"] = tls_layer.handshake_extensions_server_name

        # Server Hello detection
        if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '2':
            if hasattr(tls_layer, 'handshake_version'):
                session_data["tls_version_server"] = tls_layer.handshake_version
            if hasattr(tls_layer, 'handshake_ciphersuite'):
                cid = tls_layer.handshake_ciphersuite
                session_data["cipher_suite_id"] = cid
                name, risk = lookup_cipher(cid)
                session_data["cipher_suite_name"] = name
                session_data["cipher_risk"] = risk

        # Certificate signature algorithm detection
        if hasattr(tls_layer, 'x509af_algorithm_id'):
            sig_oid = tls_layer.x509af_algorithm_id
            session_data["signature_algorithm_oid"] = sig_oid

            if sig_oid in WEAK_SIG_ALGORITHMS:
                session_data["signature_algorithm_name"] = WEAK_SIG_ALGORITHMS[sig_oid]
                session_data["cert_risk"] = "weak - deprecated signature algorithm"
            else:
                session_data["signature_algorithm_name"] = "modern/unknown"
                session_data["cert_risk"] = "acceptable"

        # Certificate common name detection
        if hasattr(tls_layer, 'x509sat_utf8string'):
            session_data["cert_common_name"] = tls_layer.x509sat_utf8string

cap.close()

# Save to a JSON file so Person B and C can use it directly
output_filename = f"{session_data['session_id']}.json"
with open(output_filename, "w") as f:
    json.dump(session_data, f, indent=2)

print(f"Saved output to {output_filename}\n")
print("--- Session TLS Summary (JSON) ---\n")
print(json.dumps(session_data, indent=2))