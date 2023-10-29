import pyshark
import logging
import os
import argparse

logging.basicConfig(level=logging.DEBUG)

def process_file(cap_file, start_pkt, num_pkts):
    totalPkts = 0
    totalBTLE = 0
    totalWithBTATT = 0
    packet_count = 0
    packets_processed = 0
    with pyshark.FileCapture(cap_file, use_ek=True) as cap:
        for pkt in cap:
            packet_count += 1
            if start_pkt is not None and packet_count < start_pkt:
                continue
            if num_pkts is not None and packets_processed >= num_pkts:
                break
            pktStr = str(pkt)
            pktStr = pktStr.replace("\r\n", "\n")
            pktStr = pktStr.replace("\n\r", "\n")
            pktStr = pktStr.replace("\n", "\n\t")
            pktStr = "\t" + pktStr
            pktStr.rstrip("\t")
            pktStr.rstrip("\n")
            print(f":\t ------------ pkt {packet_count} ------------")
            print(pktStr)
            packets_processed += 1

            # Check if BT ATT protocol present
            if hasattr(pkt, "btatt"):
                totalWithBTATT += 1
            if hasattr(pkt, "btle"):
                totalBTLE += 1
            totalPkts += 1
    print(f"Packets Total {totalPkts} BTATT {totalWithBTATT} BTLE {totalBTLE}")

# def process_path(cap_path, mac_addr):
#     if os.path.isdir(cap_path):
#         for file in os.listdir(cap_path):
#             if file.endswith(".pcapng"):
#                 process_file(os.path.join(cap_path, file), mac_addr)
#     else:
#         process_file(cap_path, mac_addr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Show pyshark packet info')
    parser.add_argument('filename', help='pcapng file to analyze')
    # Add optional start packet number and number of packets to process
    parser.add_argument("-s", "--start", type=int, help="start packet number")
    parser.add_argument("-n", "--num", default=10, type=int, help="num packets to process")
    args = parser.parse_args()
    process_file(args.filename, args.start, args.num)
