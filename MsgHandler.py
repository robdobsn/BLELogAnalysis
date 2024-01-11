from martypy import LikeHDLC, RICProtocols
from PacketInfo import PacketInfo

class MsgHandler:
    def __init__(self, prefix, outfile, onMsg, onError=None):
        self.hdlc = LikeHDLC.LikeHDLC(self.onFrameRx, self.onError)
        self.ricProtocols = RICProtocols.RICProtocols()
        self.onMsg = onMsg
        self.onError = onError
        self.lastPacketInfo: PacketInfo = None
        self.debugInFrame = False
        self.debugLastCharWasE7 = False
        self.debugCurLine = ""
        self.prefix = prefix
        self.outfile = outfile
        self.debugCurHex = ""

    def onFrameRx(self, frame):
        # print(f"Frame received: {frame}")
        msg = self.ricProtocols.decodeRICFrame(frame)
        # print(self.lastFrameTime, msg.msgNum, len(msg.payload))
        if self.onMsg is not None:
            self.onMsg(msg, self.lastPacketInfo)

    def onError(self):
        self.outfile.write("<<CRC>>\n")
        # print(f"HDLC Error")
        if self.onError is not None:
            self.onError()

    def handle(self, msg, packetInfo: PacketInfo):
        self.lastPacketInfo = packetInfo
        for byte in msg:
            self.debugCurHex += f"{byte:02x}"
            if byte == 0xe7:
                self.outfile.write("<<E7>>")
                if self.debugLastCharWasE7 or not self.debugInFrame:
                    self.debugInFrame = True
                else:
                    if self.debugInFrame:
                        self.outfile.write(self.prefix + " ")
                        self.outfile.write(self.debugCurHex)
                        if self.debugCurLine != "":
                            self.outfile.write(" --- " + self.debugCurLine + "\n")
                            # print(f" --- {self.debugCurLine}")
                    self.debugCurLine = ""
                    self.debugCurHex = ""
                    self.debugInFrame = False
                self.debugLastCharWasE7 = True
            else:
                if not self.debugInFrame:
                    self.outfile.write("<@>")
                    # print("<@@@@@@@@>")
                self.debugLastCharWasE7 = False
            self.debugCurLine += chr(byte) if byte > 32 and byte < 128 else '.'
            self.hdlc.decodeData(byte)
