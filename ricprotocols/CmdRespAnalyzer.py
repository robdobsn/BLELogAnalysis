from PacketInfo import PacketInfo
from dataclasses import dataclass

@dataclass
class CmdResp:
    msgNum: int
    cmdTimestamp: float
    cmd: bytes
    respTimestamp: float
    resp: bytes

class CmdRespAnalyzer:

    def __init__(self, outfile):
        self.msg_tracker = {}
        self.outfile = outfile

    def ricInMsg(self, msg, packetInfo: PacketInfo):
        # print(f"{packetInfo.num} {packetInfo.timestamp} {msg.toString()}")
        # Check if message in message tracker - if so its a repeat
        if msg.msgNum in self.msg_tracker:
            print(f"Repeat message {msg.msgNum}")
        else:
            self.msg_tracker[msg.msgNum] = CmdResp(msg.msgNum, packetInfo.timestamp, msg.payload, 0, None)

    def ricOutMsg(self, msg, packetInfo: PacketInfo):
        # print(f"{packetInfo.num} {packetInfo.timestamp} {msg.toString()}")
        # Check if message in not in message tracker - if so its spurious
        if msg.msgNum not in self.msg_tracker:
            print(f"Spurious response {msg.msgNum}")
        else:
            self.msg_tracker[msg.msgNum].resp = msg.payload
            # print(f"CmdResp #{msg.msgNum} RespTime {packetInfo.timestamp - self.msg_tracker[msg.msgNum].cmdTimestamp}")
            self.outfile.write(f"CmdResp #{msg.msgNum} RespTime {round((packetInfo.timestamp - self.msg_tracker[msg.msgNum].cmdTimestamp)*1000, 1)}\n")
