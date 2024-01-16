from scapy.all import sniff

def main():
    # Sniffing continuously and writing packets to a file
    sniff(prn=ruleset_filter, store=0)

def ruleset_filter(packet):
    if (packet.haslayer("TCP") and packet[TCP].dport == 80):
        with open ("flagged_packets.txt", "a+") as file:
            file.write(packet.show(dump=True))
            file.write("\n\n")

def packet_printer(packet):
    #print(packet.show())

    # Append the packet to a file named "captured_packets.pcap"
    #wrpcap("captured_packets.txt", packet, append=True)
    with open("captured_packets.txt", "a+") as file:
        file.write(packet.show(dump=True))
        file.write("\n\n") 

if __name__ == "__main__":
    main()