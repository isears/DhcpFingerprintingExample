# DHCP Fingerprinting Example

## Task

Take the pcap file linked below and fingerprint the DHCP client stacks of the various hosts in the capture. One approach is to use the DHCP options and their order to create a unique-ish hash. For extra points, try and determine what some of the common DHCP clients fingerprint out to.


The output should be something along the lines of:
IP, hash, client metadata

## Libraries

* Required: [Dpkt](https://pypi.python.org/pypi/dpkt) - For reading pcaps
* Optional: [Requests](https://pypi.python.org/pypi/requests) - For interacting with Fingerbank API

## Usage

### Run demo with pre-fetched metadata

The fingerbank_data.json file in this repository already contains fingerprint metadata corresponding to the maccdc2012_0016.pcap. To run the demo, download the [maccdc2012_00016.pcap](https://download.netresec.com/pcap/maccdc-2012/maccdc2012_00016.pcap.gz) and unpack. Then simply run DhcpFingerprint.py:

```
python DhcpFingerprint.py maccdc2012_00016.pcap
```

### Run with any other pcap

To run DhcpFingerprint.py with any other pcap, metadata should first be retrieved from fingerbank. To do so, get a free api key at [Fingerbank](https://fingerbank.org/usage.html). Then run GetFingerbankMetadata.py (the utility will prompt for an API key):

```
python GetFingerprintMetadata.py some-other-pcap.pcap
```

GetFingerprintMetadata.py will write metadata to fingerbank_data.json for use by DhcpFingerprint.py. Once it has completed, run DhcpFingerprint.py:

```
python DhcpFingerprint.py some-other-pcap.pcap
```