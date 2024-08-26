import re
from subprocess import PIPE, Popen
import pyshark


class Reader(object):
    def __init__(self, verbose=False) -> None:
        self.verbose = verbose

    def read(self, path: str) -> str:
        if self.verbose:
            print(f"Reading from {path}")
        with open(path, "r") as f:
            return f.read()

    def tshark_version(self):
        """Returns the current version of tshark.

        Returns
        -------
        version : string
            Current version number of tshark.
        """
        # Get tshark version via command line
        command = ["tshark", "--version"]
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        out, err = process.communicate()

        # Throw error if any
        if err:
            raise ValueError("Exception in tshark version check: '{}'".format(err))

        # Search for version number
        regex = re.compile("TShark .*(\d+\.\d+\.\d+) ")
        out = out.decode("utf-8")
        version = regex.search(out).group(1)

        # Return version
        return version

    def read_http(self, path: str):
        """read pcap file and extract http packets and return features of http packets
        Args:
            path (_type_): pcap file path
        """
        # Read pcap file
        pcap = pyshark.FileCapture(path, display_filter="http")
        # Extract features of http packets
        http_features = []
        for packet in pcap:
            if hasattr(packet, "http"):
                print(f"Request Method: {packet.http.request_method}")
                print(f"Request URI: {packet.http.request_uri}")
                print(f"Response Code: {packet.http.response_code}")
                print(f"Content Type: {packet.http.content_type}")
        print(f"File Data: {packet.http.file_data}")

        return http_features
