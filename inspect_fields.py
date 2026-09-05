import pyshark

cap = pyshark.FileCapture("weak_tls_capture.pcapng", display_filter="tcp.port==4433 && tls.handshake.type==11")

for pkt in cap:
    if hasattr(pkt, 'tls'):
        print("--- All available TLS field names in this Certificate packet ---\n")
        for field_name in pkt.tls.field_names:
            value = getattr(pkt.tls, field_name)
            print(f"{field_name}: {value}")
    break  # only need to see the first matching packet

cap.close()