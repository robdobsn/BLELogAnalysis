import logging
import pyshark
import argparse
import json
import yaml
import os
import nest_asyncio
import numpy as np
from PacketAnalyzer import PacketAnalyzer
from PacketInfo import PacketInfo
from RICProtocolAnalyzer import RICProtocolAnalyzer

# Basic logging configuration
logging.basicConfig(level=logging.INFO,format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

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

def processFile(filename):
    cap = pyshark.FileCapture(filename, use_ek=True)
    blePacketAnalyzer = PacketAnalyzer(config_data,
                                        ble_services, 
                                        ble_characteristics, 
                                        ble_declarations,
                                        ble_descriptors)
    filenameonly = os.path.basename(filename)
    log.info(f"-------------- {filenameonly} --------------")
    for packet in cap:
        packet_info = PacketInfo(packet.number, packet.frame_info.time.relative)
        blePacketAnalyzer.handlePacket(packet, packet_info)
    blePacketAnalyzer.handleEndOfCaptureFile()
    # Close capture file
    cap.close()
    # Show stats
    if args.verbose:
        log.info("-------------- STATS --------------")
    blePacketAnalyzer.showStats()
    # Show RIC protocol analysis if requested
    if args.ric:
        ricProtocolAnalyzer = RICProtocolAnalyzer(config_data,
                                            blePacketAnalyzer)
        ricProtocolAnalyzer.analyzeRICProtocol()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze BLE state')
    parser.add_argument('filename', help='pcapng file to analyze - or folder with pcapng files')
    # Add argument for config json file
    parser.add_argument('--config', help='Config file', default="config.json")
    parser.add_argument('--verbose', help='Verbose output', action='store_true')
    parser.add_argument('--ric', help='Analyze RIC protocols', action='store_true')
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

    # Set asyncio policy
    nest_asyncio.apply()

    # Check file or folder
    if os.path.isdir(args.filename):
        # Process all pcapng files in folder
        for filename in os.listdir(args.filename):
            if filename.endswith(".pcapng"):
                processFile(args.filename + "/" + filename)
    else:
        # Process single file
        processFile(args.filename)

