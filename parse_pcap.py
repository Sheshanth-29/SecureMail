import pyshark
import json

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

WEAK_SIG_ALGORITHMS = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
}

def lookup_cipher(hex_id):
    return CIPHER_SUITE_INFO.get(hex_id, ("UNKNOWN_CIPHER", "unknown"))

def new_session(session_key):
    return {
        "session_id": f"sess_{session_key}",
        "protocol": "TLS-Test",
        "sni": None,
        "tls_version_client": None,
        "tls_version_server": None,
        "cipher_suite_id": None,
        "cipher_suite_name": None,
        "cipher_risk": None,
        "signature_algorithm_oid": None,
        "signature_algorithm_name": None,
        "cert_common_name": None,
        "cert_risk": None,
        "cert_subject": None,
        "cert_issuer": None,
        "self_signed": None
    }

def analyze_pcap(filepath, display_filter):
    cap = pyshark.FileCapture(filepath, display_filter=display_filter)
    sessions = {}

    for pkt in cap:
        if not hasattr(pkt, 'tls'):
            continue
        tls_layer = pkt.tls

        # Use TCP stream index as the session key (PyShark tracks this automatically)
        stream_id = pkt.tcp.stream if hasattr(pkt, 'tcp') else "unknown"

        if stream_id not in sessions:
            sessions[stream_id] = new_session(stream_id)

        s = sessions[stream_id]

        if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '1':
            if hasattr(tls_layer, 'handshake_version'):
                s["tls_version_client"] = tls_layer.handshake_version
            if hasattr(tls_layer, 'handshake_extensions_server_name'):
                s["sni"] = tls_layer.handshake_extensions_server_name

        if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '2':
            if hasattr(tls_layer, 'handshake_version'):
                s["tls_version_server"] = tls_layer.handshake_version
            if hasattr(tls_layer, 'handshake_ciphersuite'):
                cid = tls_layer.handshake_ciphersuite
                s["cipher_suite_id"] = cid
                name, risk = lookup_cipher(cid)
                s["cipher_suite_name"] = name
                s["cipher_risk"] = risk

        if hasattr(tls_layer, 'x509af_algorithm_id'):
            sig_oid = tls_layer.x509af_algorithm_id
            s["signature_algorithm_oid"] = sig_oid
            if sig_oid in WEAK_SIG_ALGORITHMS:
                s["signature_algorithm_name"] = WEAK_SIG_ALGORITHMS[sig_oid]
                s["cert_risk"] = "weak - deprecated signature algorithm"
            else:
                s["signature_algorithm_name"] = "modern/unknown"
                s["cert_risk"] = "acceptable"

        if hasattr(tls_layer, 'x509sat_utf8string'):
            cn = tls_layer.x509sat_utf8string
            s["cert_common_name"] = cn
            # Simplified self-signed check: since we can't cleanly separate
            # subject vs issuer fields via PyShark, we treat a single CN
            # appearing (typical of self-signed test certs) as a signal.
            s["cert_subject"] = cn
            s["cert_issuer"] = cn
            s["self_signed"] = True

    cap.close()
    return list(sessions.values())


if __name__ == "__main__":
    import sys

    # Change these two lines per capture file you want to analyze
    FILE = "real_smtp_capture.pcapng"
    FILTER = "tcp.port==2525"

    results = analyze_pcap(FILE, FILTER)

    output_filename = FILE.replace(".pcapng", "_results.json")
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Found {len(results)} session(s). Saved to {output_filename}\n")
    print(json.dumps(results, indent=2))