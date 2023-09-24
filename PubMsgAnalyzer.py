from martypy import RICProtocols
from martypy.RICROSSerial import RICROSSerial
from PacketInfo import PacketInfo

class PubMsgAnalyzer:

    def __init__(self, outfile):
        self.pubMsgTimestamps = {}
        self.lastPubMsgTime = 0
        self.outfile = outfile

    def handleMsg(self, msg: RICProtocols.DecodedMsg, packetInfo: PacketInfo):
        
        # print(f"{timestamp} protocol {msg.protocolID} type {msg.msgTypeCode} msgNum {msg.msgNum} payload {msg.payload}")
        # print(f"{timestamp} protocol {msg.toString()}")

        # Decode ROSSerial
        self.lastPubMsgTime = packetInfo.timestamp
        RICROSSerial.decode(msg.payload, 0, self._rxPublishedMsg)

    def _rxPublishedMsg(self, topicID: int, payload: bytes):
        pubMsgTimestamps = self.pubMsgTimestamps.get(topicID)
        if pubMsgTimestamps is None:
            self.pubMsgTimestamps[topicID] = [self.pubMsgTimestamps]
        else:
            pubMsgTimestamps.append(self.lastPubMsgTime)

    def showStats(self):
        print(f"PubMsgs {[(str(name)+':'+str(len(val))) for (name,val) in self.pubMsgTimestamps.items()]}")
