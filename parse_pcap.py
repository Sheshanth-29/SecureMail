import pyshark

# Load the capture, filtering only your session's port
cap = pyshark.FileCapture("real_smtp_capture.pcapng", display_filter="tcp.port==2525")

print("--- Inspecting session for TLS handshake details ---\n")

for pkt in cap:
    if hasattr(pkt, 'tls'):
        tls_layer = pkt.tls

        # Client Hello detection
        if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '1':
            print("Found Client Hello:")
            if hasattr(tls_layer, 'handshake_version'):
                print(f"  TLS version advertised: {tls_layer.handshake_version}")
            if hasattr(tls_layer, 'handshake_extensions_server_name'):
                print(f"  SNI (target server): {tls_layer.handshake_extensions_server_name}")
            print()

        # Server Hello detection
        if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '2':
            print("Found Server Hello:")
            if hasattr(tls_layer, 'handshake_version'):
                print(f"  TLS version negotiated: {tls_layer.handshake_version}")
            if hasattr(tls_layer, 'handshake_ciphersuite'):
                print(f"  Cipher suite chosen: {tls_layer.handshake_ciphersuite}")
            print()

cap.close()