import logging
import pyshark
import argparse
import json
import yaml
import numpy as np
from PacketInfo import PacketInfo

# Basic logging configuration
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

ble_dev_addr_packet_paths = [
    "btle.advertising.address"
]
ble_pdu_type_packet_paths = [
    "btle.advertising.header.pdu.type"
]
ble_pdu_type_labels = {
    0: "ADV_IND", 
    1: "ADV_DIRECT_IND",
    2: "ADV_NONCONN_IND",
    3: "SCAN_REQ", 
    4: "SCAN_RESP",
    5: "CONNECT_IND",
    6: "ADV_SCAN_IND",
    7: "ADV_EXT_IND",
    8: "AUX_CONNECT_RSP"
}
ble_control_opcode_paths = [
    "btle.control.opcode"
]
ble_control_opcode_labels = {
    0: "LL_CONNECTION_UPDATE_IND",
    1: "LL_CHANNEL_MAP_IND",
    2: "LL_TERMINATE_IND",
    3: "LL_ENC_REQ",
    4: "LL_ENC_RSP",
    5: "LL_START_ENC_REQ",
    6: "LL_START_ENC_RSP",
    7: "LL_UNKNOWN_RSP",
    8: "LL_FEATURE_REQ",
    9: "LL_FEATURE_RSP",
    10: "LL_PAUSE_ENC_REQ",
    11: "LL_PAUSE_ENC_RSP",
    12: "LL_VERSION_IND",
    13: "LL_REJECT_IND",
    14: "LL_SLAVE_FEATURE_REQ",
    15: "LL_CONNECTION_PARAM_REQ",
    16: "LL_CONNECTION_PARAM_RSP",
    17: "LL_REJECT_EXT_IND",
    18: "LL_PING_REQ",
    19: "LL_PING_RSP",
    20: "LL_LENGTH_REQ",
    21: "LL_LENGTH_RSP",
    22: "LL_PHY_REQ",
    23: "LL_PHY_RSP",
    24: "LL_PHY_UPDATE_IND",
    25: "LL_MIN_USED_CHANNELS_IND",
    26: "LL_CTE_REQ",
    27: "LL_CTE_RSP",
    28: "LL_PERIODIC_SYNC_IND",
    29: "LL_CLOCK_ACCURACY_REQ",
    30: "LL_CLOCK_ACCURACY_RSP",
}
ble_feature_req_bits = [
    ["LE Encryption","ENC"],
    ["Connection Parameters Request Procedure","CPRP"],
    ["Extended Reject Indication","EXTREJ"],
    ["Slave-initiated Features Exchange","SLVFEAT"],
    ["LE Ping","PING"],
    ["LE Data Packet Length Extension","DLE"],
    ["LL Privacy","PRIV"],
    ["Extended Scanner Filter Policies","SCANFILT"],
    ["LE 2M PHY","2M"],
    ["Stable Modulation Index - Transmitter","STMODTX"],
    ["Stable Modulation Index - Receiver","STMODRX"],
    ["LE Coded PHY","CODED"],
    ["LE Extended Advertising","EXTADV"],
    ["LE Periodic Advertising","PERADV"],
    ["Channel Selection Algorithm #2","CHSEL2"],
    ["LE Power Class 1","PWRC1"],
    ["Minimum Number of Used Channels Procedure","MINCHPROC"],
]
ble_att_opcode_paths = [
    "btatt.opcode.method"
]
ble_att_method_labels = {
    1: "ATT_ERROR_RSP",
    2: "ATT_EXCHANGE_MTU_REQ",
    3: "ATT_EXCHANGE_MTU_RSP",
    4: "ATT_FIND_INFO_REQ",
    5: "ATT_FIND_INFO_RSP",
    6: "ATT_FIND_BY_TYPE_VALUE_REQ",
    7: "ATT_FIND_BY_TYPE_VALUE_RSP",
    8: "ATT_READ_BY_TYPE_REQ",
    9: "ATT_READ_BY_TYPE_RSP",
    10: "ATT_READ_REQ",
    11: "ATT_READ_RSP",
    12: "ATT_READ_BLOB_REQ",
    13: "ATT_READ_BLOB_RSP",
    14: "ATT_READ_MULTIPLE_REQ",
    15: "ATT_READ_MULTIPLE_RSP",
    16: "ATT_READ_BY_GROUP_TYPE_REQ",
    17: "ATT_READ_BY_GROUP_TYPE_RSP",
    18: "ATT_WRITE_REQ",
    19: "ATT_WRITE_RSP",
    20: "ATT_WRITE_CMD",
    21: "ATT_SIGNED_WRITE_CMD",
    22: "ATT_PREPARE_WRITE_REQ",
    23: "ATT_PREPARE_WRITE_RSP",
    24: "ATT_EXECUTE_WRITE_REQ",
    25: "ATT_EXECUTE_WRITE_RSP",
    26: "ATT_HANDLE_VALUE_NOTIFICATION",
    27: "ATT_HANDLE_VALUE_INDICATION",
    28: "ATT_HANDLE_VALUE_CONFIRMATION",
    0x52: "ATT_WRITE_CMD",
    0xD2: "ATT_WRITE_CMD_SIGNED",
}

class BLEStateAnalyzer:

    def __init__(self, config_data,
                ble_services,
                ble_characteristics,
                ble_declarations,
                ble_descriptors,
                bleDeviceAddr = "") -> None:
        self.config_data = config_data
        self.ble_services = ble_services
        self.ble_characteristics = ble_characteristics
        self.ble_declarations = ble_declarations
        self.ble_descriptors = ble_descriptors
        self.bleDeviceAddr = bleDeviceAddr
        if self.bleDeviceAddr == "":
            if "bleDeviceAddr" in self.config_data:
                self.bleDeviceAddr = self.config_data["bleDeviceAddr"]
        self.state_sequence = []
        self.cur_state = {}

    def timeFormat(self, timestamp):
        return f"{timestamp:.3f}"
        
    def checkPacketPath(self, pysh_pkt, packetPaths):
        for packetPath in packetPaths:
            field_ok = True
            fields = packetPath.split(".")
            obt_to_test = pysh_pkt
            for field in fields:
                if hasattr(obt_to_test, field):
                    obt_to_test = getattr(obt_to_test, field)
                else:
                    field_ok = False
                    break
            if field_ok:
                return field_ok, obt_to_test, packetPath
        return False, None, None

    def getAdvInfo(self, pdu_types):
        adv_info = ""
        for i in range(0, len(pdu_types[0])):
            if pdu_types[0][i] > 0:
                adv_info += f"{ble_pdu_type_labels[i]} {pdu_types[0][i]} "
        return adv_info
    
    def handleEndOfAdvState(self):  
        # Get average interval between ADV_IND packets
        advIndIntervals = None
        if "advIndTimes" in self.cur_state:
            advIndTimes = np.array(self.cur_state["advIndTimes"])
            advIndIntervals = advIndTimes[1:] - advIndTimes[:-1]
            advIndIntervals = advIndIntervals * 1000
            advIndIntervals = np.round(advIndIntervals)
        # Summarize activity to this point if any
        if "pduType" in self.cur_state:
            pdu_types = np.histogram(self.cur_state["pduType"], bins=range(0, len(ble_pdu_type_labels)))
            out_str = f"{self.cur_state['firstPktTime']} {self.cur_state['firstPktNum']}-{self.cur_state['lastPktNum']} "
            out_str += f"Advertising "
            if advIndIntervals is not None:
                out_str += f"Interval {np.mean(advIndIntervals):.0f}ms "
            out_str += f"{self.getAdvInfo(pdu_types)}"
            log.debug(out_str)
            self.state_sequence.append(self.cur_state)
            self.cur_state = {}
    
    def summarizeConnection(self, conn_info):
        # Summarize connection
        conn_summary = {}
        if "dataFrames" in conn_info:
            if len(conn_info["dataFrames"]) > 0:
                # log.debug(f"Data frames: {len(conn_info['dataFrames'])}")
                for dataFrame in conn_info["dataFrames"]:
                    if dataFrame["characteristic"] not in conn_summary:
                        conn_summary[dataFrame["characteristic"]] = {}
                    if dataFrame["type"] not in conn_summary[dataFrame["characteristic"]]:
                        conn_summary[dataFrame["characteristic"]][dataFrame["type"]] = {
                            "dataLen":0,
                            "pktCount":0
                        }
                    rec = conn_summary[dataFrame["characteristic"]][dataFrame["type"]]
                    rec["dataLen"] += len(dataFrame["data"])
                    rec["pktCount"] += 1
                    # log.debug(f"{self.timeFormat(dataFrame['time'])} {dataFrame['type']} {dataFrame['characteristic']} {dataFrame['data'].hex()}")
        for characteristic in conn_summary:
            for msg_type in conn_summary[characteristic]:
                rec = conn_summary[characteristic][msg_type]
                log.info(f"{characteristic} {msg_type} Packets {rec['pktCount']} Bytes {rec['dataLen']}")

    def handleConnInd(self, pysh_pkt, packet_info: PacketInfo):
        # Handle end of advertising state if reequired
        self.handleEndOfAdvState()
        # Connect indication
        log.debug(f"{self.timeFormat(packet_info.timestamp)} {packet_info.num} CONNECT_IND")

    def handleTerminateInd(self, pysh_pkt):
        self.state_sequence.append(self.cur_state)
        self.cur_state = {}

    def extractFeatures(self, pysh_pkt):
        features = ""
        featureSet = int(pysh_pkt.btle.control.feature.set.value)
        bitmask = 1
        for i in range(0, len(ble_feature_req_bits)):
            if featureSet & bitmask:
                features += ble_feature_req_bits[i][1] + " "
            bitmask = bitmask << 1
        return features
    
    def handleLLOpcode(self, opcode, pysh_pkt, packet_info: PacketInfo):
        # Handle specific opcodes
        out_str = f"{self.timeFormat(packet_info.timestamp)} {packet_info.num} "
        if opcode == 0: # LL_CONNECTION_UPDATE_IND
            out_str += f"LL_CONNECTION_UPDATE_IND Interval {pysh_pkt.btle.control.interval} Latency {pysh_pkt.btle.control.latency} Timeout {pysh_pkt.btle.control.timeout}"
        elif opcode == 1: # LL_CHANNEL_MAP_IND
            out_str += f"LL_CHANNEL_MAP_IND {pysh_pkt.btle.control.channel_map}"
        elif opcode == 2: # LL_TERMINATE_IND
            out_str += f"LL_TERMINATE_IND {self.handleTerminateInd(pysh_pkt)}"
        elif opcode == 3: # LL_ENC_REQ
            out_str += f"LL_ENC_REQ"
        elif opcode == 4: # LL_ENC_RSP
            out_str += f"LL_ENC_RSP"
        elif opcode == 5: # LL_START_ENC_REQ
            out_str += f"LL_START_ENC_REQ"
        elif opcode == 6: # LL_START_ENC_RSP
            out_str += f"LL_START_ENC_RSP"
        elif opcode == 7: # LL_UNKNOWN_RSP
            out_str += f"LL_UNKNOWN_RSP"
        elif opcode == 8: # LL_FEATURE_REQ
            out_str += f"LL_FEATURE_REQ {self.extractFeatures(pysh_pkt)}"
        elif opcode == 9: # LL_FEATURE_RSP
            out_str += f"LL_FEATURE_RSP {self.extractFeatures(pysh_pkt)}"
        elif opcode == 10: # LL_PAUSE_ENC_REQ
            out_str += f"LL_PAUSE_ENC_REQ"
        elif opcode == 11: # LL_PAUSE_ENC_RSP
            out_str += f"LL_PAUSE_ENC_RSP"
        elif opcode == 12: # LL_VERSION_IND
            out_str += f"LL_VERSION_IND"
        elif opcode == 13: # LL_REJECT_IND
            out_str += f"LL_REJECT_IND"
        elif opcode == 14: # LL_SLAVE_FEATURE_REQ
            out_str += f"LL_SLAVE_FEATURE_REQ {self.extractFeatures(pysh_pkt)}"
        elif opcode == 15: # LL_CONNECTION_PARAM_REQ
            out_str += f"LL_CONNECTION_PARAM_REQ Interval Min {pysh_pkt.btle.control.interval.min} ({pysh_pkt.btle.control.interval.min*1.25}ms) Max {pysh_pkt.btle.control.interval.max} ({pysh_pkt.btle.control.interval.max*1.25}ms) Latency {pysh_pkt.btle.control.latency} Timeout {pysh_pkt.btle.control.timeout}"
        elif opcode == 16: # LL_CONNECTION_PARAM_RSP
            out_str += f"LL_CONNECTION_PARAM_RSP Interval Min {pysh_pkt.btle.control.interval.min} ({pysh_pkt.btle.control.interval.min*1.25}ms) Max {pysh_pkt.btle.control.interval.max} ({pysh_pkt.btle.control.interval.max*1.25}ms) Latency {pysh_pkt.btle.control.latency} Timeout {pysh_pkt.btle.control.timeout}"
        elif opcode == 17: # LL_REJECT_EXT_IND
            out_str += f"LL_REJECT_EXT_IND"
        elif opcode == 18: # LL_PING_REQ
            out_str += f"LL_PING_REQ"
        elif opcode == 19: # LL_PING_RSP
            out_str += f"LL_PING_RSP"
        elif opcode == 20: # LL_LENGTH_REQ
            out_str += f"LL_LENGTH_REQ TxMax {pysh_pkt.btle.control.max.tx.octets} TxTime {pysh_pkt.btle.control.max.tx.time} RxMax {pysh_pkt.btle.control.max.rx.octets} RxTime {pysh_pkt.btle.control.max.rx.time}"
        elif opcode == 21: # LL_LENGTH_RSP
            out_str += f"LL_LENGTH_RSP TxMax {pysh_pkt.btle.control.max.tx.octets} TxTime {pysh_pkt.btle.control.max.tx.time} RxMax {pysh_pkt.btle.control.max.rx.octets} RxTime {pysh_pkt.btle.control.max.rx.time}"
        elif opcode == 22: # LL_PHY_REQ
            out_str += f"LL_PHY_REQ Tx {pysh_pkt.btle.control.tx_phy} Rx {pysh_pkt.btle.control.rx_phy}"
        elif opcode == 23: # LL_PHY_RSP
            out_str += f"LL_PHY_RSP Tx {pysh_pkt.btle.control.tx_phy} Rx {pysh_pkt.btle.control.rx_phy}"
        elif opcode == 24: # LL_PHY_UPDATE_IND
            out_str += f"LL_PHY_UPDATE_IND Tx {pysh_pkt.btle.control.tx_phy} Rx {pysh_pkt.btle.control.rx_phy}"
        elif opcode == 25: # LL_MIN_USED_CHANNELS_IND
            out_str += f"LL_MIN_USED_CHANNELS_IND {pysh_pkt.btle.control.min_used_channels}"
        else:
            out_str += f"{packet_info.num} Opcode {opcode}"
        log.debug(out_str)

    def getBTATTHandles(self, pysh_pkt):
        if hasattr(pysh_pkt.btatt, "starting") and hasattr(pysh_pkt.btatt, "ending"):
            return f"{pysh_pkt.btatt.starting.handle} - {pysh_pkt.btatt.ending.handle}"
        elif hasattr(pysh_pkt.btatt, "handle"):
            return f"{pysh_pkt.btatt.handle}"
        else:
            return "Unknown"

    def uuidLookup(self, uuid):
        if uuid in self.ble_services:
            return '"' + self.ble_services[uuid] + '"'
        if uuid in self.ble_characteristics:
            return '"' + self.ble_characteristics[uuid] + '"'
        if uuid in self.ble_declarations:
            return '"' + self.ble_declarations[uuid] + '"'
        if uuid in self.ble_descriptors:
            return '"' + self.ble_descriptors[uuid] + '"'
        if uuid in self.config_data["uuids"]:
            return '"' + self.config_data["uuids"][uuid] + '"'
        uuid_byte_reversed = "".join([uuid[i:i+2] for i in range(len(uuid), -1, -2)])
        if uuid_byte_reversed in self.config_data["uuids"]:
            return '"' + self.config_data["uuids"][uuid_byte_reversed] + '"(REVERSED)'
        return "0x" + uuid
    
    def getUUIDHexStr(self, rec):
        if hasattr(rec, "uuid128"):
            rec_uuid128 = rec.uuid128
            if isinstance(rec_uuid128, list):
                uuidList = ""
                for uuid in rec_uuid128:
                    uuidList += self.uuidLookup(f"{uuid.hex()}") + " "
                return uuidList
            else:
                return self.uuidLookup(f"{rec.uuid128.hex()}")
        elif hasattr(rec, "uuid16"):
            uuid16 = rec.uuid16
            if isinstance(uuid16, list):
                uuidList = ""
                for uuid in uuid16:
                    uuidList += self.uuidLookup(f"{uuid:04x}") + " "
            else:
                return self.uuidLookup(f"{rec.uuid16:04x}")
        else:
            return "Unknown"

    def getServiceUUID(self, btatt):
        if hasattr(btatt, "service"):
            return self.getUUIDHexStr(btatt.service)
        return "Unknown"
            
    def getCharUUID(self, btatt):
        if hasattr(btatt, "characteristic"):
            return self.getUUIDHexStr(btatt.characteristic)
        return self.getUUIDHexStr(btatt)

    def getValueData(self, btatt, msg_type, characteristic):
        if hasattr(btatt, "value"):
            if "dataFrames" not in self.cur_state:
                self.cur_state["dataFrames"] = []
            self.cur_state["dataFrames"].append(
                {
                    "time":packet_info.timestamp,
                    "data":btatt.value,
                    "type":msg_type,
                    "characteristic":characteristic
                })
            return(f"Length {len(btatt.value)} Data {btatt.value.hex()}")
        else:
            return "No data"

    def handleATTMethod(self, method, pysh_pkt, packet_info: PacketInfo):
        out_str = f"{self.timeFormat(packet_info.timestamp)} {packet_info.num} "
        # Handle specific methods
        if method == 2: # ATT_MTU_REQ
            out_str += f"ATT_MTU_REQ CLIENT RX MTU {pysh_pkt.btatt.client.rx.mtu}"
        elif method == 3: # ATT_MTU_RSP
            out_str += f"ATT_MTU_RSP SERVER RX MTU {pysh_pkt.btatt.server.rx.mtu}"
        elif method == 4: # ATT_FIND_INFO_REQ
            out_str += f"ATT_FIND_INFO_REQ Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 5: # ATT_FIND_INFO_RSP
            out_str += f"ATT_FIND_INFO_RSP Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 8: # ATT_READ_BY_TYPE_REQ
            out_str += f"ATT_READ_BY_TYPE_REQ Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 9: # ATT_READ_BY_TYPE_RSP
            out_str += f"ATT_READ_BY_TYPE_RSP Service {self.getServiceUUID(pysh_pkt.btatt)} Attribute {self.getCharUUID(pysh_pkt.btatt)}"
        elif method == 10: # ATT_READ_REQ
            out_str += f"ATT_READ_REQ Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 11: # ATT_READ_RSP
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_READ_RSP Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(pysh_pkt.btatt, 'READ_RSP', characteristic)}"
        elif method == 16: # ATT_READ_BY_GROUP_TYPE_REQ
            out_str += f"ATT_READ_BY_GROUP_TYPE_REQ Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 17: # ATT_READ_BY_GROUP_TYPE_RSP
            out_str += f"ATT_READ_BY_GROUP_TYPE_RSP Service {self.getServiceUUID(pysh_pkt.btatt)} Attribute {self.getCharUUID(pysh_pkt.btatt)}"
        elif method == 18: # ATT_WRITE_REQ
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_WRITE_REQ Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(pysh_pkt.btatt, 'WRITE_REQ', characteristic)}"
        elif method == 19: # ATT_WRITE_RSP
            out_str += f"ATT_WRITE_RSP Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 20: # ATT_WRITE_CMD
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_WRITE_CMD Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(pysh_pkt.btatt, 'WRITE_CMD', characteristic)}"
        elif method == 26: # ATT_HANDLE_VALUE_NOTIFICATION
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_HANDLE_VALUE_NOTIFICATION Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(pysh_pkt.btatt, 'VALUE_NOTIFY', characteristic)}"
        elif method == 27: # ATT_HANDLE_VALUE_INDICATION
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_HANDLE_VALUE_INDICATION Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(pysh_pkt.btatt, 'VALUE_IND', characteristic)}"
        else:
            out_str += f"ATT method {method}"
        log.debug(out_str)

    def handlePacket(self, pysh_pkt, packet_info: PacketInfo):
        # Check if device address is to be discovered
        if self.bleDeviceAddr == "":
            field_ok, field_val, _ = self.checkPacketPath(pysh_pkt, ble_dev_addr_packet_paths)
            if field_ok:
                self.bleDeviceAddr = field_val
                log.debug(f"BLE device address: {self.bleDeviceAddr}")

        # Check if device address is specified
        if self.bleDeviceAddr == "":
            return
        
        # PDU type
        field_ok, field_val, packetPath = self.checkPacketPath(pysh_pkt, ble_pdu_type_packet_paths)
        if field_ok:
            if "pduType" not in self.cur_state:
                self.cur_state["pduType"] = []
            self.cur_state["pduType"].append(field_val)
            if field_val == 5: # CONNECT_IND
                self.handleConnInd(pysh_pkt, packet_info)
            else:
                if field_val == 0: # ADV_IND
                    if "advIndTimes" not in self.cur_state:
                        self.cur_state["advIndTimes"] = []
                    self.cur_state["advIndTimes"].append(packet_info.timestamp)
                if "firstPktNum" not in self.cur_state:
                    self.cur_state["firstPktNum"] = packet_info.num
                    self.cur_state["firstPktTime"] = packet_info.timestamp
                self.cur_state["lastPktNum"] = packet_info.num

        # LL Opcode
        field_ok, field_val, packetPath = self.checkPacketPath(pysh_pkt, ble_control_opcode_paths)
        if field_ok:
            self.handleLLOpcode(field_val, pysh_pkt, packet_info)

        # ATT opcode
        field_ok, field_val, packetPath = self.checkPacketPath(pysh_pkt, ble_att_opcode_paths)
        if field_ok:
            self.handleATTMethod(field_val, pysh_pkt, packet_info)
 
    def showStats(self):
        for state in self.state_sequence:
            if "dataFrames" in state:
                self.summarizeConnection(state)
        # log.debug(self.cur_state)

def readConfig(config_file_name):
    # Read json config file
    with open(config_file_name) as config_file:
        config_data = json.load(config_file)
        return config_data

def readYamlUUIDS(yaml_file_name):
    # Read yaml file
    with open(yaml_file_name) as yaml_file:
        yaml_data = yaml.load(yaml_file, Loader=yaml.FullLoader)
        uuid_data = {f"{serv['uuid']:04x}":serv['name'] for serv in yaml_data["uuids"]}
        return uuid_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze BLE state')
    parser.add_argument('filename', help='pcapng file to analyze')
    # Add argument for config json file
    parser.add_argument('--config', help='Config file', default="config.json")
    parser.add_argument('--verbose', help='Verbose output', action='store_true')
    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    # Read service and characteristics from YAML files
    ble_services = readYamlUUIDS("service_uuids.yaml")
    ble_characteristics = readYamlUUIDS("characteristic_uuids.yaml")
    ble_declarations = readYamlUUIDS("declaration_uuids.yaml")
    ble_descriptors = readYamlUUIDS("descriptor_uuids.yaml")

    # Read UUIDs and names
    config_data = readConfig(args.config)
    cap = pyshark.FileCapture(args.filename, use_ek=True)
    bleStateAnalyzer = BLEStateAnalyzer(config_data, 
                                        ble_services, 
                                        ble_characteristics, 
                                        ble_declarations,
                                        ble_descriptors)
    for packet in cap:
        packet_info = PacketInfo(packet.number, packet.frame_info.time.relative)
        bleStateAnalyzer.handlePacket(packet, packet_info)
    bleStateAnalyzer.handleEndOfAdvState()
    log.info("-------------- STATS --------------")
    bleStateAnalyzer.showStats()
