import pyshark
from CommsAnalyzer import CommsAnalyzer
from PacketInfo import PacketInfo
import logging
import os

logging.basicConfig(level=logging.DEBUG)

# baseFolder = R"C:\Users\rob\Downloads\blesniffs\202307BLETestLogs"
baseFolder = R"M:\RobDev\Projects\BotsCNC\Marty\BLETests\20230924BLETestLogs"
logsFolder = R"logs"

L2CAP_CmdRej=1
L2CAP_ConnReq=2
L2CAP_ConnResp=3
L2CAP_ConfReq=4
L2CAP_ConfResp=5
L2CAP_DisconnReq=6
L2CAP_DisconnResp=7
L2CAP_EchoReq=8
L2CAP_EchoResp=9
L2CAP_InfoReq=10
L2CAP_InfoResp=11
L2CAP_CreateChanReq=12
L2CAP_CreateChanResp=13
L2CAP_MoveChanReq=14
L2CAP_MoveChanResp=15
L2CAP_MoveChanCnf=16
L2CAP_MoveChanCnfResp=17
L2CAP_Connection_Parameter_Update_Request=18
L2CAP_Connection_Parameter_Update_Response=19
L2CAP_LE_Credit_Based_Connection_Request=20
L2CAP_LE_Credit_Based_Connection_Response=21
L2CAP_LE_Flow_Control_Credit=22

ATT_Error_Response=0x1
ATT_Exchange_MTU_Request=0x2
ATT_Exchange_MTU_Response=0x3
ATT_Find_Information_Request=0x4
ATT_Find_Information_Response=0x5
ATT_Find_By_Type_Value_Request=0x6
ATT_Find_By_Type_Value_Response=0x7
ATT_Read_By_Type_Request=0x8
ATT_Read_By_Type_Request_128bit=0x8
ATT_Read_By_Type_Response=0x9
ATT_Read_Request=0xa
ATT_Read_Response=0xb
ATT_Read_Blob_Request=0xc
ATT_Read_Blob_Response=0xd
ATT_Read_Multiple_Request=0xe
ATT_Read_Multiple_Response=0xf
ATT_Read_By_Group_Type_Request=0x10
ATT_Read_By_Group_Type_Response=0x11
ATT_Write_Request=0x12
ATT_Write_Response=0x13
ATT_Prepare_Write_Request=0x16
ATT_Prepare_Write_Response=0x17
ATT_Execute_Write_Request=0x18
ATT_Execute_Write_Response=0x19
ATT_Handle_Value_Notification=0x1b
ATT_Handle_Value_Indication=0x1d
ATT_Handle_Value_Confirmation=0x1e
ATT_Write_Command=0x52

ATT_Dict = {
    ATT_Error_Response: "Error Response",
    ATT_Exchange_MTU_Request: "Exchange MTU Request",
    ATT_Exchange_MTU_Response: "Exchange MTU Response",
    ATT_Find_Information_Request: "Find Information Request",
    ATT_Find_Information_Response: "Find Information Response",
    ATT_Find_By_Type_Value_Request: "Find By Type Value Request",
    ATT_Find_By_Type_Value_Response: "Find By Type Value Response",
    ATT_Read_By_Type_Request: "Read By Type Request",
    ATT_Read_By_Type_Request_128bit: "Read By Type Request 128bit",
    ATT_Read_By_Type_Response: "Read By Type Response",
    ATT_Read_Request: "Read Request",
    ATT_Read_Response: "Read Response",
    ATT_Read_Blob_Request: "Read Blob Request",
    ATT_Read_Blob_Response: "Read Blob Response",
    ATT_Read_Multiple_Request: "Read Multiple Request",
    ATT_Read_Multiple_Response: "Read Multiple Response",
    ATT_Read_By_Group_Type_Request: "Read By Group Type Request",
    ATT_Read_By_Group_Type_Response: "Read By Group Type Response",
    ATT_Write_Request: "Write Request",
    ATT_Write_Response: "Write Response",
    ATT_Prepare_Write_Request: "Prepare Write Request",
    ATT_Prepare_Write_Response: "Prepare Write Response",
    ATT_Execute_Write_Request: "Execute Write Request",
    ATT_Execute_Write_Response: "Execute Write Response",
    ATT_Handle_Value_Notification: "Handle Value Notification",
    ATT_Handle_Value_Indication: "Handle Value Indication",
    ATT_Handle_Value_Confirmation: "Handle Value Confirmation",
    ATT_Write_Command: "Write Command"
}

def analyzeFile(filename):
    fname, fext = os.path.splitext(filename)
    outfilename = os.path.join(logsFolder, fname + ".txt")
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
                    outfile.write(f"## {packetInfo.num} {packetInfo.timestamp} MTU req {mtu_size}\n")
                    # print(f"MTU {mtu_size}")
                elif packet.btatt.opcode.method == 3: # MTU response
                    mtu_size = int(packet.btatt._fields_dict["btatt_btatt_server_rx_mtu"])
                    outfile.write(f"## {packetInfo.num} {packetInfo.timestamp} MTU resp {mtu_size}\n")
                    # print(f"MTU {mtu_size}")
                elif packet.btatt.opcode.method == 0x1b or packet.btatt.opcode.method == 0x1d: # Handle value notification / indication
                    # print(f"BTATT {packet.btatt.value}")
                    if hasattr(packet.btatt, "value"):
                        outfile.write(f"== {packetInfo.num} {packetInfo.timestamp} {ATT_Dict[packet.btatt.opcode.method]} {packet.btatt.value.hex()}\n")
                        commsAnalyzer.ricOutMsg(packet.btatt.value, packetInfo)
                    else:
                        outfile.write(f"== {packetInfo.num} {packetInfo.timestamp} {ATT_Dict[packet.btatt.opcode.method]} NO PAYLOAD\n")
                elif packet.btatt.opcode.method == 0x12: # Write request
                    if hasattr(packet.btatt, "value"):
                        outfile.write(f"== {packetInfo.num} {packetInfo.timestamp} {ATT_Dict[packet.btatt.opcode.method]} {packet.btatt.value.hex()}\n")
                        commsAnalyzer.ricInMsg(packet.btatt.value, packetInfo)
                    else:
                        outfile.write(f"== {packetInfo.num} {packetInfo.timestamp} {ATT_Dict[packet.btatt.opcode.method]} NO PAYLOAD\n")
                elif packet.btatt.opcode.method in ATT_Dict:
                    outfile.write(f"## {packetInfo.num} {packetInfo.timestamp} {ATT_Dict[packet.btatt.opcode.method]}\n")
                else:
                    outfile.write(f"## UNKNOWN {packetInfo.num} {packetInfo.timestamp} {packet.btatt.opcode}\n")

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


# slave_mac = "b8:d6:1a:bc:6e:96"
slave_mac = "c4:de:e2:c2:1e:ae"

# Iterate files in folder
for filename in os.listdir(baseFolder):
    if filename.endswith(".pcapng"):
        analyzeFile(filename)
