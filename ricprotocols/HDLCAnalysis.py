class HDLCAnalysis:

    def __init__(self):
        pass

    def expectedDelim(self, packet_info, msg, byte_idx):
        # A delimiter was expected 
        print(f"Delimiter expected byteIdx {byte_idx} {msg}")
