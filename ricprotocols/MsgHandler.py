from martypy import LikeHDLC, RICProtocols
from PacketInfo import PacketInfo
from ricprotocols.HDLCAnalysis import HDLCAnalysis

class MsgHandler:
    def __init__(self, prefix, outfile, onMsg, onError=None):
        self.hdlc = LikeHDLC.LikeHDLC(self.onFrameRx, self.onError)
        self.ricProtocols = RICProtocols.RICProtocols()
        self.onMsg = onMsg
        self.onError = onError
        self.lastPacketInfo: PacketInfo = None
        self.debugInFrame = False
        self.debugLastCharWasDelimiter = False
        self.debugCurLine = ""
        self.prefix = prefix
        self.outfile = outfile
        self.debugCurHex = ""
        self.hdlc_analysis = HDLCAnalysis()
        self.hdlc_delimiter = 0xe7

    def onFrameRx(self, frame):
        # print(f"Frame received: {frame}")
        msg = self.ricProtocols.decodeRICFrame(frame)
        # print(self.lastFrameTime, msg.msgNum, len(msg.payload))
        if self.onMsg is not None:
            self.onMsg(msg, self.lastPacketInfo)

    def onError(self):
        if self.outfile:
            self.outfile.write("<<CRC>>")
        # print(f"HDLC Error")
        if self.onError is not None:
            self.onError()

    def handle(self, msg, packetInfo: PacketInfo):
        self.lastPacketInfo = packetInfo
        print(f"{self.lastPacketInfo}")
        missingDelimReportedForMsg = False
        for byte_idx, byte in enumerate(msg):
            self.debugCurHex += f"{byte:02x}"
            if byte == self.hdlc_delimiter:
                if self.outfile:
                    self.outfile.write("<<E7>>")
                if self.debugLastCharWasDelimiter or not self.debugInFrame:
                    self.debugInFrame = True
                else:
                    if self.debugInFrame:
                        if self.outfile:
                            self.outfile.write(self.prefix + " ")
                            self.outfile.write(self.debugCurHex)
                            if self.debugCurLine != "":
                                self.outfile.write(" --- " + self.debugCurLine + "\n")
                                # print(f" --- {self.debugCurLine}")
                    self.debugCurLine = ""
                    self.debugCurHex = ""
                    self.debugInFrame = False
                self.debugLastCharWasDelimiter = True
            else:
                if not self.debugInFrame:
                    if self.outfile:
                        self.outfile.write("<@>")
                    # print("<@@@@@@@@>")
                    if not missingDelimReportedForMsg:
                        self.hdlc_analysis.expectedDelim(packetInfo, msg, byte_idx)
                        missingDelimReportedForMsg = True
                self.debugLastCharWasDelimiter = False
            self.debugCurLine += chr(byte) if byte > 32 and byte < 128 else '.'
            self.hdlc.decodeData(byte)
