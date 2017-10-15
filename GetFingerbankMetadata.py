import requests
import json
import sys
import dpkt
import getpass

from DhcpFingerprint import dhcp_packet_generate, safe_open, raw_opts_to_fingerbank_str, FINGERBANK_JSON_FILE_NAME

API_ENDPOINT = "https://api.fingerbank.org/api/v2/combinations/interrogate"


def usage():
    print "Utility to download dhcp fingerprint metadata from fingerbank - Isaac Sears 2017-10-15"
    print "Usage: python", sys.argv[0], "some-pcap.pcap"
    print "\tsome-pcap.pcap: the pcap to search for dhcp fingerprints."
    sys.exit()


# Interact with API to retrieve metadata corresponding to dhcp fingerprints
def get_fingerbank_fingerprints(dhcp_fingerprints):
    api_key = getpass.getpass("Enter API key: ")
    res = list()

    for fp_json in dhcp_fingerprints:
        print "[*] Retrieving data for:", fp_json
        resp = requests.get(API_ENDPOINT, params={"key": api_key}, data=json.loads(fp_json))

        # Test for errors: 200 means fingerprint found, 404 means fingerprint not found, all others indicate error
        if resp.status_code != 200 and resp.status_code != 404:
            print "[-] There was an error while interacting with the fingerbank api"
            print "\tStatus code:", str(resp.status_code)
            print "\tText:", resp.text
            sys.exit()

        res_data = json.loads(resp.text)
        res_data["fingerprint"] = json.loads(fp_json)

        res.append(res_data)

    # Write data to file as JSON
    with open(FINGERBANK_JSON_FILE_NAME, "w") as dumpfile:
        json.dump(res, dumpfile)


def main():
    fingerprints = set()
    print "[*] Iterating through pcap, looking for dhcp fingerprints"
    for ip_src_str, dhcp in dhcp_packet_generate(dpkt.pcap.Reader(safe_open(sys.argv[1]))):
        fingerprint = dict()
        dhcp_opts_dict = dict(dhcp.opts)

        if dpkt.dhcp.DHCP_OPT_PARAM_REQ in dhcp_opts_dict:  # Use DHCP option 55 to fingerprint DHCP stack
            fingerprint["dhcp_fingerprint"] = raw_opts_to_fingerbank_str(dhcp_opts_dict[dpkt.dhcp.DHCP_OPT_PARAM_REQ])

            if dpkt.dhcp.DHCP_OPT_VENDOR_ID in dhcp_opts_dict:  # Also look for vendor id
                fingerprint["vendor_id"] = dhcp_opts_dict[dpkt.dhcp.DHCP_OPT_VENDOR_ID]

            fingerprints.add(json.dumps(fingerprint))  # Build set of unique fingerprints

    print "[+] Done iterating through pcap"

    # Politely ask before interacting with API
    print "[*] Found a total of", len(fingerprints), "unique fingerprints. Proceed to interact with API?"
    decision = raw_input("Y for yes, any other character for no: ")

    if decision == "Y":
        get_fingerbank_fingerprints(list(fingerprints))
    else:
        print "Exiting..."
        sys.exit()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    else:
        main()
