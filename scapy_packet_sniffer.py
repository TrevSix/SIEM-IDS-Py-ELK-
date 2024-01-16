from scapy.all import sniff

def main():
    ruleset_filter = "tcp and (port 80 or port 22 or port 443)" 
    user_in = input("Please enter any additional filters you'd like in Berkeley Packet Filter format. \nIncluded by default are TCP ports 80, 443, and 22. \nYour filter here: ")
    if user_in != "":
        ruleset_filter = ruleset_filter + ' or ' + user_in
    # Sniffing continuously and writing packets to a file
    print("Filtering by: " + ruleset_filter)
    try:
        sniff(prn=packet_printer, filter=ruleset_filter)
    except PermissionError as e:
        print("Error Caught in BPF: {e}")
        print("Please check your filter and try again.")

def packet_printer(packet):
    #print(packet.show())

    # Append the packet to a file named "captured_packets.pcap"
    #wrpcap("captured_packets.txt", packet, append=True)
    with open("captured_packets.txt", "a+") as file:
        file.write(packet.show(dump=True))
        file.write("\n\n") 

if __name__ == "__main__":
    main()