import dpkt
import json
import socket
import sys

DHCP_CLIENT_DST_PORT = 67  # DHCP client must send datagram with destination port 67 (RFC 2131)
DHCP_UNINITIALIZED_ADDR_STR = "0.0.0.0"
FINGERBANK_JSON_FILE_NAME = "fingerbank_data.json"  # JSON file containing data pulled from fingerbank databases
NOT_FOUND_LOCALLY_DEVICE_NAME = "Unknown (not found in local " + FINGERBANK_JSON_FILE_NAME + " file)"
UNKNOWN_DEVICE_NAME = "Unknown (fingerbank does not have device name)"


def usage():
    print "DHCP Fingerprinting example - Isaac Sears 2017-10-15"
    print "Usage: python", sys.argv[0], "some-pcap.pcap"
    print "\tsome-pcap.pcap: the pcap to search for dhcp fingerprints."
    sys.exit()


# Check file exists before opening
def safe_open(file_name):
    try:
        f = open(file_name)
    except IOError:
        print "[-] Error: could not find file:", file_name, "exiting..."
        sys.exit()

    return f


# Generator function filters out all packets that are not dhcp client packets as it iterates through pcap
def dhcp_packet_generate(pcap):
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):  # Throw away non-IP traffic
            continue

        ip = eth.data

        if not isinstance(ip.data, dpkt.udp.UDP):  # Throw away non-UDP traffic
            continue

        udp = ip.data

        if udp.dport == DHCP_CLIENT_DST_PORT:  # Found DHCP client packet.
            ip_src_str = socket.inet_ntoa(ip.src)

            try:  # Test to ensure this is a real DHCP packet
                dhcp = dpkt.dhcp.DHCP(udp.data)
            except dpkt.NeedData:
                continue

            yield ip_src_str, dhcp


# Python list comprehensions to format the dhcp options into a fingerbank-readable fingerprint
def raw_opts_to_fingerbank_str(raw_opts):
    return ",".join([str(ord(x)) for x in raw_opts])


def main():
    fingerbank_data = json.load(safe_open(FINGERBANK_JSON_FILE_NAME))
    result = set()

    # Iterate through dhcp packets in pcap
    for ip_src_str, dhcp in dhcp_packet_generate(dpkt.pcap.Reader(safe_open(sys.argv[1]))):

        dhcp_opts_dict = dict(dhcp.opts)

        # Attempt to find initialized ip addr for this client, either in ip header or dhcp requested ip addr
        if ip_src_str == DHCP_UNINITIALIZED_ADDR_STR:
            if dpkt.dhcp.DHCP_OPT_REQ_IP in dhcp_opts_dict:
                ip_src_str = socket.inet_ntoa(dhcp_opts_dict[dpkt.dhcp.DHCP_OPT_REQ_IP])
            else:
                continue

        if dpkt.dhcp.DHCP_OPT_PARAM_REQ in dhcp_opts_dict:  # Use DHCP option 55 to fingerprint DHCP stack
            curr_fingerprint = dict()
            curr_fingerprint["dhcp_fingerprint"] = \
                raw_opts_to_fingerbank_str(dhcp_opts_dict[dpkt.dhcp.DHCP_OPT_PARAM_REQ])

            if dpkt.dhcp.DHCP_OPT_VENDOR_ID in dhcp_opts_dict:  # Include vendor id, if present
                curr_fingerprint["vendor_id"] = dhcp_opts_dict[dpkt.dhcp.DHCP_OPT_VENDOR_ID]

            # Python list comprehensions to find fingerbank metadata associations based on a fingerprint
            fingerbank_lookup_result = \
                next((item for item in fingerbank_data if cmp(item["fingerprint"], curr_fingerprint) == 0), None)

            # Process results (or lack thereof) of fingerbank lookup
            if fingerbank_lookup_result is None:
                device_name = NOT_FOUND_LOCALLY_DEVICE_NAME
            elif "device_name" in fingerbank_lookup_result:
                device_name = fingerbank_lookup_result["device_name"]
            else:
                device_name = UNKNOWN_DEVICE_NAME

            # Build set of unique fingerprint/ip combinations
            result.add((ip_src_str, json.dumps(curr_fingerprint), device_name))

    result = list(result)
    result.sort(key=lambda x: socket.inet_aton(x[0]))  # Sort by IP address

    for item in result:
        print item[0] + "," + item[1] + "," + item[2]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    else:
        main()
