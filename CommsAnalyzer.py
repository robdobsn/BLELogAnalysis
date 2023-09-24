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
        self.outMsgs.handle(msg, packetInfo)

    def ricInMsg(self, msg: DecodedMsg, packetInfo: PacketInfo):
        self.inMsgs.handle(msg, packetInfo)

    def onDecodedRicOut(self, msg: DecodedMsg, packetInfo: PacketInfo):
        # print("Out", msg, timestamp)
        if msg.protocolID == RICProtocols.PROTOCOL_ROSSERIAL:
            if msg.msgTypeCode == RICProtocols.MSG_TYPE_PUBLISH:
                self.pubMsgAnalyser.handleMsg(msg, packetInfo)
        elif msg.protocolID == RICProtocols.PROTOCOL_RICREST:
            if msg.msgTypeCode == RICProtocols.MSG_TYPE_RESPONSE:
                self.cmdRespAnalyzer.ricOutMsg(msg, packetInfo)

    def onDecodedRicIn(self, msg: DecodedMsg, packetInfo: PacketInfo):
        if msg.protocolID == RICProtocols.PROTOCOL_RICREST:
            if msg.msgTypeCode == RICProtocols.MSG_TYPE_COMMAND:
                self.cmdRespAnalyzer.ricInMsg(msg, packetInfo)

    def showStats(self):
        self.pubMsgAnalyser.showStats()



    