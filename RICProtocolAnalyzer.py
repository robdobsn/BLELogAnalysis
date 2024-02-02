from ricprotocols.RICCommsAnalyzer import RICCommsAnalyzer
from PacketInfo import PacketInfo

class RICProtocolAnalyzer:

    def __init__(self, config_data, packet_analyzer) -> None:
        self.config_data = config_data
        self.packet_analyzer = packet_analyzer

    def analyzeRICProtocol(self) -> None:
        # TODO replace with log to file
        with open("test.txt", "w") as outfile:
            comms_analyzer = RICCommsAnalyzer(outfile)
            # Get the state sequence from the packet_analyzer
            comms_phases = self.packet_analyzer.getStateSequence()
            # Iterate comms phases (advertising/connection)
            for comms_phase in comms_phases:
                if "dataFrames" in comms_phase:
                    for data_frame in comms_phase["dataFrames"]:
                        packet_info = PacketInfo(data_frame["num"], data_frame["time"])
                        packet_data = data_frame["data"]
                        characteristic = data_frame["characteristic"]
                        # print(f"Process char {characteristic} num {packet_info.num} ts {packet_info.timestamp} len {len(packet_data)}")
                        # Check characteristic
                        if characteristic == "RIC2_RSP":
                            comms_analyzer.ricOutMsg(packet_data, packet_info)
                        elif characteristic == "RIC2_CMD":
                            comms_analyzer.ricInMsg(packet_data, packet_info)


                    #     if 
                    #                         if hasattr(packet.btatt, "value"):
                    #         commsAnalyzer.ricOutMsg(packet.btatt.value, packetInfo)
                    # elif packet.btatt.opcode.method == 0x12: # Write request
                    #     if hasattr(packet.btatt, "value"):
                    #         commsAnalyzer.ricInMsg(packet.btatt.value, packetInfo)
