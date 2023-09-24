import pyshark
from CommsAnalyzer import CommsAnalyzer
from PacketInfo import PacketInfo
import logging
import os

logging.basicConfig(level=logging.DEBUG)

baseFolder = R"C:\Users\rob\Downloads\blesniffs\202307BLETestLogs"

def analyzeFile(filename):
    fname, fext = os.path.splitext(filename)
    outfilename = os.path.join(baseFolder, fname + ".txt")
    with open(outfilename, "w") as outfile:
        cap = pyshark.FileCapture(os.path.join(baseFolder, filename), use_ek=True)
        commsAnalyzer = CommsAnalyzer(outfile)
        # print(cap[1].show())

        # Select BLE packets on MAC b8:d6:1a:bc:6e:96
        # pktNum = 5037 #4784
        for packet in cap:
            # Check if slave address is the one required
            # if hasattr(packet.btle, "slave") and packet.btle.slave.bd.addr == slave_mac:
            #     break

            # Check if BT ATT protocol present
            if hasattr(packet, "btatt"):
                packetInfo = PacketInfo(packet.number, packet.frame_info.time.relative)
                if packet.btatt.opcode.method == 2: # MTU size
                    mtu_size = int(packet.btatt._fields_dict["btatt_btatt_client_rx_mtu"])
                    print(f"MTU {mtu_size}")
                elif packet.btatt.opcode.method == 0x1b: # Handle value notification
                    # print(f"BTATT {packet.btatt.value}")
                    if hasattr(packet.btatt, "value"):
                        commsAnalyzer.ricOutMsg(packet.btatt.value, packetInfo)
                elif packet.btatt.opcode.method == 0x12: # Write request
                    if hasattr(packet.btatt, "value"):
                        commsAnalyzer.ricInMsg(packet.btatt.value, packetInfo)

            # if packet.number == pktNum:
            #     break

            # if not isConn:
            #     if packet.btle.advertising_header.pdu_type == 5:
            #         if packet.highest_layer != "_WS_MALFORMED":
            #             print("conn")
            #             isConn = True
            # else:
            #     break
                        
            # if "scanning" in packet.btle.field_names or "scan" in packet.btle.field_names:
            #     continue
            # print(packet.btle)
            # if ("btle" in packet) and ("slave_bd_addr" in packet.btle) and (packet.btle.slave_bd_addr == "b8:d6:1a:bc:6e:96"):
            #     print(packet.btle.show())
            #     break

        commsAnalyzer.showStats()


slave_mac = "b8:d6:1a:bc:6e:96"

# Iterate files in folder
for filename in os.listdir(baseFolder):
    if filename.endswith(".pcapng"):
        analyzeFile(filename)
