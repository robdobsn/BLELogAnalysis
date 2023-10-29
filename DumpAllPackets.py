import pyshark

with pyshark.FileCapture("example.pcapng", use_ek=True) as cap:
    for pkt in cap:
        pkt.show()
        