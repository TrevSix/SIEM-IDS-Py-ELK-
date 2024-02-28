import json, time, urllib3
from elasticsearch import Elasticsearch
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw

#Disable CONSTANT warnings about verify_certs=False being bad. IK!
urllib3.disable_warnings()

#Set up this information for the indexing 
elastic_host="https://10.4.20.69:9200"

client = Elasticsearch(
  elastic_host,
  #ca_certs="/etc/elasticsearch/certs/http_ca.crt",
  verify_certs=False,
  api_key="SDktZzA0MEJUc3Njend4UnJlTWQ6eTkyYWJ5MnJRRnE2c2NzU1hyRUNodw=="
)

# Exclude traffic between elastic server and agent on ports 9200 or 8220 to avoid feedback loop. 
excluded_source_ip = "10.4.20.69"
excluded_dest_ip = "10.4.20.70"
excluded_source_port = 9200


def packet_sniffer(packet):

    # Check source and destination IP addresses
    ip_layer = packet.getlayer(IP)
    tcp_layer = packet.getlayer(TCP)
    if (
        hasattr(ip_layer, "src") and
        hasattr(ip_layer, "dst") and
        ((ip_layer.src == excluded_source_ip and ip_layer.dst == excluded_dest_ip) or
        (ip_layer.src == excluded_dest_ip and ip_layer.dst == excluded_source_ip))
    ):
        # Check source and destination ports in the TCP layer
        if (
            tcp_layer and
            ((hasattr(tcp_layer, "sport") and tcp_layer.sport in {9200, 8220}) or
            (hasattr(tcp_layer, "dport") and tcp_layer.dport in {9200, 8220}))
        ):
            # Exclude the packet and return without processing
            return

    #Create dictionary to parse data into to make JSON
    data = {}

    # Grab timestamp for ID
    timestamp = str(time.time())

    # Ethernet Layer
    ethernet_layer = packet.getlayer(Ether)
    if ethernet_layer is not None:
        data[f"ethernet.dst"] = str(ethernet_layer.dst)
        data[f"ethernet.src"] = str(ethernet_layer.src)
        data[f"ethernet.type"] = str(ethernet_layer.type)

    # IP Layer
    if ip_layer is not None:
        data[f"ip.version"] = str(ip_layer.version)
        data[f"ip.ihl"] = str(ip_layer.ihl)
        data[f"ip.tos"] = str(ip_layer.tos)
        data[f"ip.len"] = str(ip_layer.len)
        data[f"ip.id"] = str(ip_layer.id)
        data[f"ip.flags"] = str(ip_layer.flags)
        data[f"ip.frag"] = str(ip_layer.frag)
        data[f"ip.ttl"] = str(ip_layer.ttl)
        data[f"ip.proto"] = str(ip_layer.proto)
        data[f"ip.chksum"] = str(ip_layer.chksum)
        data[f"ip.src"] = str(ip_layer.src)
        data[f"ip.dst"] = str(ip_layer.dst)

    # Check for and process TCP layer
    if tcp_layer is not None:
        data[f"tcp.sport"] = str(tcp_layer.sport)
        data[f"tcp.dport"] = str(tcp_layer.dport)
        data[f"tcp.seq"] = str(tcp_layer.seq)
        data[f"tcp.ack"] = str(tcp_layer.ack)
        data[f"tcp.dataofs"] = str(tcp_layer.dataofs)
        data[f"tcp.reserved"] = str(tcp_layer.reserved)
        data[f"tcp.flags"] = str(tcp_layer.flags)
        data[f"tcp.window"] = str(tcp_layer.window)
        data[f"tcp.chksum"] = str(tcp_layer.chksum)
        data[f"tcp.urgptr"] = str(tcp_layer.urgptr)
        data[f"tcp.options"] = str(tcp_layer.options)

    # Check for and process UDP layer
    if UDP in packet:
        udp_layer = packet.getlayer(UDP)
        data[f"udp.sport"] = str(udp_layer.sport)
        data[f"udp.dport"] = str(udp_layer.dport)
        data[f"udp.len"] = str(udp_layer.len)
        data[f"udp.chksum"] = str(udp_layer.chksum)

    # Check for and process ICMP layer
    if ICMP in packet:
        icmp_layer = packet.getlayer(ICMP)
        data[f"icmp.type"] = str(icmp_layer.type)
        data[f"icmp.code"] = str(icmp_layer.code)
        data[f"icmp.chksum"] = str(icmp_layer.chksum)

    # Check for and process Raw layer
    if Raw in packet:
        raw_layer = packet.getlayer(Raw)
        data[f"raw.load"] = str(raw_layer.load)

    # Convert the dictionary to JSON
    packet_json = json.dumps(data, indent=2)

    #print(packet_json) -- test tool

    # Send it to the Elasticsearch server
    client.index(index="search-agent_index",id=timestamp, body=packet_json) #-- uncomment to send data

# Use the sniff function with the prn parameter to define the callback function
sniff(prn=packet_sniffer, store=0)