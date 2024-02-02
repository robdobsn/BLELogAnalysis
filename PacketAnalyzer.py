import logging
import pyshark
import numpy as np
from PacketInfo import PacketInfo

# Basic logging configuration
logging.basicConfig(level=logging.INFO,format='%(levelname)s: %(message)s')
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
    ["LE Encryption","ENC", False],
    ["Connection Parameters Request Procedure","CPRP", False],
    ["Extended Reject Indication","EXTREJ", False],
    ["Slave-initiated Features Exchange","SLVFEAT", False],
    ["LE Ping","PING", False],
    ["LE Data Packet Length Extension","DLE", True],
    ["LL Privacy","PRIV", False],
    ["Extended Scanner Filter Policies","SCANFILT", False],
    ["LE 2M PHY","2M", True],
    ["Stable Modulation Index - Transmitter","STMODTX", False],
    ["Stable Modulation Index - Receiver","STMODRX", False],
    ["LE Coded PHY","CODED", True],
    ["LE Extended Advertising","EXTADV", False],
    ["LE Periodic Advertising","PERADV", False],
    ["Channel Selection Algorithm #2","CHSEL2", False],
    ["LE Power Class 1","PWRC1", False],
    ["Minimum Number of Used Channels Procedure","MINCHPROC", False],
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

class PacketAnalyzer:

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

    def getStateSequence(self):
        return self.state_sequence

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
    
    def handleEndOfCaptureFile(self):
        self.handleEndOfAdvState()
        self.handleEndOfConnection()

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
        # Features
        if "FEATURE_RSP" in conn_info:
            log.info(f"IMPORTANT FEATURES {conn_info['FEATURE_RSP']}")

        # DLE
        if "DLE" in conn_info:
            txMax = conn_info["DLE"]["txMax"]
            txTime = conn_info["DLE"]["txTime"]
            rxMax = conn_info["DLE"]["rxMax"]
            rxTime = conn_info["DLE"]["rxTime"]
            log.info(f"DLE (Data Length Extension) TxMax {txMax} TxTime {txTime} RxMax {rxMax} RxTime {rxTime}")

        # MTU
        if "RX_MTU" in conn_info:
            log.info(f"RX MTU {conn_info['RX_MTU']}")

        # Connection interval
        if "UPDATE_IND" in conn_info:
            interval = conn_info["UPDATE_IND"]["interval"]
            latency = conn_info["UPDATE_IND"]["latency"]
            timeout = conn_info["UPDATE_IND"]["timeout"]
            log.info(f"CONNECTION Interval {interval} ({interval*1.25}ms) Latency {latency} Timeout {timeout}")

        # PHY
        if "PHY_UPDATE_IND" in conn_info:
            phy = conn_info["PHY_UPDATE_IND"]["phy"]
            coded = conn_info["PHY_UPDATE_IND"]["coded"]
            log.info(f"PHY PHY {phy}m CODED:{'YES' if coded else 'NO'}")
        else:
            log.info(f"PHY PHY 1m CODED:NO")

        # Calculate maximum theoretical throughput (rx)
        if "UPDATE_IND" in conn_info and "RX_MTU" in conn_info:
            assumption_max_packets_per_conn_interval = 6
            interval_us = conn_info["UPDATE_IND"]["interval"] * 1.25 * 1000
            latency = conn_info["UPDATE_IND"]["latency"]
            timeout = conn_info["UPDATE_IND"]["timeout"]
            rx_mtu = conn_info["RX_MTU"]
            data_len = 27 if "DLE" not in conn_info else conn_info["DLE"]["rxMax"]
            if rx_mtu < data_len:
                data_len = rx_mtu
            packet_time_us = (data_len + 14) * 8 + 380
            num_packets_in_interval = interval_us // packet_time_us
            if num_packets_in_interval > assumption_max_packets_per_conn_interval:
                num_packets_in_interval = assumption_max_packets_per_conn_interval
            throughput_bytes_per_sec = 1000 * num_packets_in_interval * data_len / interval_us
            if "PHY_UPDATE_IND" in conn_info:
                phy = conn_info["PHY_UPDATE_IND"]["phy"]
                if phy == 2:
                    throughput_bytes_per_sec *= 1.8
            log.info(f"APPROX MAX THROUGHPUT {throughput_bytes_per_sec:.2f} kBytes/s ({num_packets_in_interval} packets per interval)")

        # Data frames
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
        self.handleEndOfConnection()

    def handleEndOfConnection(self):
        if "UPDATE_IND" in self.cur_state or "dataFrames" in self.cur_state:
            self.state_sequence.append(self.cur_state)
        self.cur_state = {}

    def extractFeatures(self, pysh_pkt, feature_type):
        features = ""
        important_features = ""
        featureSet = int(pysh_pkt.btle.control.feature.set.value)
        bitmask = 1
        for i in range(0, len(ble_feature_req_bits)):
            if featureSet & bitmask:
                features += ble_feature_req_bits[i][1] + " "
                if ble_feature_req_bits[i][2]:
                    important_features += ble_feature_req_bits[i][1] + ":YES "
            elif ble_feature_req_bits[i][2]:
                features += f"({ble_feature_req_bits[i][1]}:NO) "
                important_features += f"{ble_feature_req_bits[i][1]}:NO "
            bitmask = bitmask << 1
        self.cur_state[feature_type] = important_features
        return features
    
    def extractDLE(self, pysh_pkt):
        txMax = pysh_pkt.btle.control.max.tx.octets
        txTime = pysh_pkt.btle.control.max.tx.time
        rxMax = pysh_pkt.btle.control.max.rx.octets
        rxTime = pysh_pkt.btle.control.max.rx.time
        self.cur_state["DLE"] = {
            "txMax":txMax,
            "txTime":txTime,
            "rxMax":rxMax,
            "rxTime":rxTime
        }
        return f"TxMax {txMax} TxTime {txTime} RxMax {rxMax} RxTime {rxTime}"
    
    def extractInterval(self, pysh_pkt, interval_type):
        interval = pysh_pkt.btle.control.interval
        latency = pysh_pkt.btle.control.latency
        timeout = pysh_pkt.btle.control.timeout
        self.cur_state[interval_type] = {
            "interval":interval,
            "latency":latency,
            "timeout":timeout
        }
        return interval, latency, timeout
    
    def extractIntervalMinMax(self, pysh_pkt, interval_type):
        interval_min = pysh_pkt.btle.control.interval.min
        interval_max = pysh_pkt.btle.control.interval.max
        latency = pysh_pkt.btle.control.latency
        timeout = pysh_pkt.btle.control.timeout
        self.cur_state[interval_type] = {
            "interval_min":interval_min,
            "interval_max":interval_max,
            "latency":latency,
            "timeout":timeout
        }
        return interval_min, interval_max, latency, timeout

    def extractPhy(self, pysh_pkt, phy_type):
        phy = 2 if hasattr(pysh_pkt.btle.control, "phys") and pysh_pkt.btle.control.phys.le.get_field("2m").get_field("phy") else 1
        coded = hasattr(pysh_pkt.btle.control, "phys") and pysh_pkt.btle.control.phys.le.coded.phy
        self.cur_state[phy_type] = {
            "phy":phy,
            "coded":coded
        }
        return phy, coded
    
    def handleLLOpcode(self, opcode, pysh_pkt, packet_info: PacketInfo):
        # Handle specific opcodes
        out_str = f"{self.timeFormat(packet_info.timestamp)} {packet_info.num} "
        if opcode == 0: # LL_CONNECTION_UPDATE_IND
            interval, latency, timeout = self.extractInterval(pysh_pkt, "UPDATE_IND")
            out_str += f"LL_CONNECTION_UPDATE_IND Interval {interval} ({interval*1.25}ms) Latency {latency} Timeout {timeout}"
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
            out_str += f"LL_FEATURE_REQ {self.extractFeatures(pysh_pkt, 'FEATURE_REQ')}"
        elif opcode == 9: # LL_FEATURE_RSP
            out_str += f"LL_FEATURE_RSP {self.extractFeatures(pysh_pkt, 'FEATURE_RSP')}"
        elif opcode == 10: # LL_PAUSE_ENC_REQ
            out_str += f"LL_PAUSE_ENC_REQ"
        elif opcode == 11: # LL_PAUSE_ENC_RSP
            out_str += f"LL_PAUSE_ENC_RSP"
        elif opcode == 12: # LL_VERSION_IND
            out_str += f"LL_VERSION_IND"
        elif opcode == 13: # LL_REJECT_IND
            out_str += f"LL_REJECT_IND"
        elif opcode == 14: # LL_SLAVE_FEATURE_REQ
            out_str += f"LL_SLAVE_FEATURE_REQ {self.extractFeatures(pysh_pkt, 'SLAVE_FEATURE_REQ')}"
        elif opcode == 15: # LL_CONNECTION_PARAM_REQ
            interval_min, interval_max, latency, timeout = self.extractIntervalMinMax(pysh_pkt, "PARAM_REQ")
            out_str += f"LL_CONNECTION_PARAM_REQ Interval Min {interval_min} ({interval_min*1.25}ms) Max {interval_max} ({interval_max*1.25}ms) Latency {latency} Timeout {timeout}"
        elif opcode == 16: # LL_CONNECTION_PARAM_RSP
            interval_min, interval_max, latency, timeout = self.extractIntervalMinMax(pysh_pkt, "PARAM_RSP")
            out_str += f"LL_CONNECTION_PARAM_RSP Interval Min {interval_min} ({interval_min*1.25}ms) Max {interval_max} ({interval_max*1.25}ms) Latency {latency} Timeout {timeout}"
        elif opcode == 17: # LL_REJECT_EXT_IND
            out_str += f"LL_REJECT_EXT_IND"
        elif opcode == 18: # LL_PING_REQ
            out_str += f"LL_PING_REQ"
        elif opcode == 19: # LL_PING_RSP
            out_str += f"LL_PING_RSP"
        elif opcode == 20: # LL_LENGTH_REQ
            out_str += f"LL_LENGTH_REQ {self.extractDLE(pysh_pkt)}"
        elif opcode == 21: # LL_LENGTH_RSP
            out_str += f"LL_LENGTH_RSP {self.extractDLE(pysh_pkt)}"
        elif opcode == 22: # LL_PHY_REQ
            phy, coded = self.extractPhy(pysh_pkt, "PHY_REQ")
            out_str += f"LL_PHY_REQ PHY {phy}m CODED:{'YES' if coded else 'NO'}"
        elif opcode == 23: # LL_PHY_RSP
            phy, coded = self.extractPhy(pysh_pkt, "PHY_REQ")
            out_str += f"LL_PHY_RSP PHY {phy} CODED:{'YES' if coded else 'NO'}"
        elif opcode == 24: # LL_PHY_UPDATE_IND
            phy, coded = self.extractPhy(pysh_pkt, "PHY_UPDATE_IND")
            out_str += f"LL_PHY_UPDATE_IND PHY {phy}m CODED:{'YES' if coded else 'NO'}"
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

    def getValueData(self, packet_info, btatt, msg_type, characteristic):
        if hasattr(btatt, "value"):
            if "dataFrames" not in self.cur_state:
                self.cur_state["dataFrames"] = []
            self.cur_state["dataFrames"].append(
                {
                    "num":packet_info.num,
                    "time":packet_info.timestamp,
                    "data":btatt.value,
                    "type":msg_type,
                    "characteristic":characteristic.replace('"','')
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
            self.cur_state["RX_MTU"] = pysh_pkt.btatt.server.rx.mtu
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
            out_str += f"ATT_READ_RSP Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(packet_info, pysh_pkt.btatt, 'READ_RSP', characteristic)}"
        elif method == 16: # ATT_READ_BY_GROUP_TYPE_REQ
            out_str += f"ATT_READ_BY_GROUP_TYPE_REQ Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 17: # ATT_READ_BY_GROUP_TYPE_RSP
            out_str += f"ATT_READ_BY_GROUP_TYPE_RSP Service {self.getServiceUUID(pysh_pkt.btatt)} Attribute {self.getCharUUID(pysh_pkt.btatt)}"
        elif method == 18: # ATT_WRITE_REQ
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_WRITE_REQ Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(packet_info, pysh_pkt.btatt, 'WRITE_REQ', characteristic)}"
        elif method == 19: # ATT_WRITE_RSP
            out_str += f"ATT_WRITE_RSP Handle {self.getBTATTHandles(pysh_pkt)}"
        elif method == 20: # ATT_WRITE_CMD
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_WRITE_CMD Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(packet_info, pysh_pkt.btatt, 'WRITE_CMD', characteristic)}"
        elif method == 26: # ATT_HANDLE_VALUE_NOTIFICATION
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_HANDLE_VALUE_NOTIFICATION Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(packet_info, pysh_pkt.btatt, 'VALUE_NOTIFY', characteristic)}"
        elif method == 27: # ATT_HANDLE_VALUE_INDICATION
            characteristic = self.getCharUUID(pysh_pkt.btatt)
            out_str += f"ATT_HANDLE_VALUE_INDICATION Handle {self.getBTATTHandles(pysh_pkt)} Service {self.getServiceUUID(pysh_pkt.btatt)} Characteristic {characteristic} {self.getValueData(packet_info, pysh_pkt.btatt, 'VALUE_IND', characteristic)}"
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

