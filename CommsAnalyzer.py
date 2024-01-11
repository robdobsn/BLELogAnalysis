from MsgHandler import MsgHandler
from PubMsgAnalyzer import PubMsgAnalyzer
from CmdRespAnalyzer import CmdRespAnalyzer
from martypy.RICProtocols import RICProtocols
from martypy.RICProtocols import DecodedMsg
from PacketInfo import PacketInfo

class CommsAnalyzer:

    def __init__(self, outfile):
        self.inMsgs = MsgHandler("IN", outfile, self.onDecodedRicIn)
        self.outMsgs = MsgHandler("OUT", outfile, self.onDecodedRicOut)
        self.pubMsgAnalyser = PubMsgAnalyzer(outfile)
        self.cmdRespAnalyzer = CmdRespAnalyzer(outfile)
        self.outfile = outfile

    def ricOutMsg(self, msg: DecodedMsg, packetInfo: PacketInfo):
        self.logPacketInfo("OUT", msg, packetInfo)
        self.outMsgs.handle(msg, packetInfo)

    def ricInMsg(self, msg: DecodedMsg, packetInfo: PacketInfo):
        self.logPacketInfo("IN", msg, packetInfo)
        self.inMsgs.handle(msg, packetInfo)

    def onDecodedRicOut(self, msg: DecodedMsg, packetInfo: PacketInfo):
        # print("Out", msg, timestamp)
        if msg.protocolID == RICProtocols.PROTOCOL_ROSSERIAL:
            if msg.msgTypeCode == RICProtocols.MSG_TYPE_PUBLISH:
                self.outfile.write(f"PUB {packetInfo.num} {packetInfo.timestamp} {msg.payload.hex()}\n")
                self.pubMsgAnalyser.handleMsg(msg, packetInfo)
            else:
                self.outfile.write(f"OUT_ROSSERIAL {packetInfo.num} {packetInfo.timestamp} msgTypeCode {msg.msgTypeCode}\n")
        elif msg.protocolID == RICProtocols.PROTOCOL_RICREST:
            if msg.msgTypeCode == RICProtocols.MSG_TYPE_RESPONSE:
                self.outfile.write(f"RESP {packetInfo.num} {packetInfo.timestamp} {msg.payload}\n")
                self.cmdRespAnalyzer.ricOutMsg(msg, packetInfo)
            else:
                self.outfile.write(f"OUT_RICREST {packetInfo.num} {packetInfo.timestamp} msgTypeCode {msg.msgTypeCode}\n")
        else:
            self.outfile.write(f"OUT_UNKNOWN {packetInfo.num} {packetInfo.timestamp} protocolID {msg.protocolID}\n")

    def onDecodedRicIn(self, msg: DecodedMsg, packetInfo: PacketInfo):
        if msg.protocolID == RICProtocols.PROTOCOL_RICREST:
            if msg.msgTypeCode == RICProtocols.MSG_TYPE_COMMAND:
                self.outfile.write(f"CMD {packetInfo.num} {packetInfo.timestamp} {msg.payload}\n")
                self.cmdRespAnalyzer.ricInMsg(msg, packetInfo)
            else:
                self.outfile.write(f"IN_RICREST {packetInfo.num} {packetInfo.timestamp} msgTypeCode {msg.msgTypeCode}\n")
        else:
            self.outfile.write(f"IN_UNKNOWN {packetInfo.num} {packetInfo.timestamp} protocolID {msg.protocolID}\n")

    def showStats(self):
        self.pubMsgAnalyser.showStats()

    def logPacketInfo(self, direction, msg: bytes, packetInfo: PacketInfo):
        self.outfile.write(f"== {direction} {packetInfo.num} {packetInfo.timestamp} {msg.hex()} \n")

    