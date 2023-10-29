import sys
import re
from scapy.all import *
from memory_profiler import profile


# @profile
# def get_url_from_payload(payload):
#     http_header_regex = r"(?P<name>.*?): (?P<value>.*?)\r\n"
#     start = payload.index(b"GET ") +4
#     end = payload.index(b" HTTP/1.1")
#     url_path = payload[start:end].decode("utf8")
#     http_header_raw = payload[:payload.index(b"\r\n\r\n") + 2 ]
#     http_header_parsed = dict(re.findall(http_header_regex, http_header_raw.decode("utf8")))
#     url = http_header_parsed["Host"] + url_path + "\n"
#     return url

@profile
def parse_pcap(pcap_path, urls_file):
    pcap_flow = rdpcap(pcap_path)
    sessions = pcap_flow.sessions()
    # urls_output = open(urls_file, "wb")
    for session in sessions:
        for packet in sessions[session]:
            print(packet.show())
            # try:
            #     if packet[TCP].dport == 80:
            #         payload = bytes(packet[TCP].payload)
            #         url = get_url_from_payload(payload)
            #         urls_output.write(url.encode())
            # except Exception as e:
            #     pass
    # urls_output.close()

def main(arguments):
    # if len(arguments) == 5:
    #     if arguments[1] == "--pcap" and arguments[3] == "--output":
    #         parse_pcap(arguments[2], arguments[4])
    parse_pcap(R"C:\Users\rob\Downloads\Asus C232N WebApp Rev5 v1.2.46 + 1st Attempt.pcapng", "test.txt")

if __name__ == "__main__":
    main(sys.argv)