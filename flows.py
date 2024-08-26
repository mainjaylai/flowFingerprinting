import pyshark
from datetime import datetime


class IpFlow:
    def __init__(self):
        self.timestamp = None
        self.src_ip = None
        self.dst_ip = None
        self.protocol = None
        self.ttl = None
        self.total_length = None
        self.identification = None
        self.flags = None
        self.fragment_offset = None
        self.header_length = None

    def add_ip_info(self, packet):
        if hasattr(packet, "ip"):
            self.timestamp = packet.sniff_timestamp
            self.src_ip = packet.ip.src
            self.dst_ip = packet.ip.dst
            self.protocol = packet.ip.proto
            self.ttl = packet.ip.ttl
            self.total_length = packet.ip.len
            self.identification = packet.ip.id
            self.flags = packet.ip.flags
            self.fragment_offset = packet.ip.frag_offset
            self.header_length = packet.ip.hdr_len


class TcpFlow(IpFlow):
    def __init__(self):
        super().__init__()
        self.src_port = None
        self.dst_port = None
        self.seq_num = None
        self.ack_num = None
        self.window_size = None
        self.tcp_flags = None
        self.tcp_options = None
        self.mss = None
        self.window_scale = None
        self.sack_permitted = None

    def add_tcp_info(self, packet):
        super().add_ip_info(packet)
        if hasattr(packet, "tcp"):
            self.src_port = packet.tcp.srcport
            self.dst_port = packet.tcp.dstport
            self.seq_num = packet.tcp.seq
            self.ack_num = packet.tcp.ack
            self.window_size = packet.tcp.window_size
            self.tcp_flags = packet.tcp.flags
            self.tcp_options = getattr(packet.tcp, "options", None)

            # Parse TCP options
            if hasattr(packet.tcp, "options_mss"):
                self.mss = packet.tcp.options_mss
            if hasattr(packet.tcp, "options_wscale"):
                self.window_scale = packet.tcp.options_wscale
            if hasattr(packet.tcp, "options_sack_perm"):
                self.sack_permitted = True


class HttpFlow(TcpFlow):
    def __init__(self):
        super().__init__()
        # Request attributes
        self.method = None
        self.uri = None
        self.version = None
        self.host = None
        self.user_agent = None
        self.accept = None
        self.accept_encoding = None
        self.accept_language = None
        self.referer = None
        self.cookie = None
        # Response attributes
        self.status_code = None
        self.content_type = None
        self.content_length = None
        self.server = None
        self.set_cookie = None
        # Common attributes
        self.connection = None
        self.cache_control = None

    def add_http_info(self, packet):
        super().add_tcp_info(packet)
        if hasattr(packet, "http"):
            http = packet.http
            # Request fields
            self.method = getattr(http, "request_method", None)
            self.uri = getattr(http, "request_uri", None)
            self.version = getattr(http, "request_version", None)
            self.host = getattr(http, "host", None)
            self.user_agent = getattr(http, "user_agent", None)
            self.accept = getattr(http, "accept", None)
            self.accept_encoding = getattr(http, "accept_encoding", None)
            self.accept_language = getattr(http, "accept_language", None)
            self.referer = getattr(http, "referer", None)
            self.cookie = getattr(http, "cookie", None)
            # Response fields
            self.status_code = getattr(http, "response_code", None)
            self.content_type = getattr(http, "content_type", None)
            self.content_length = getattr(http, "content_length", None)
            self.server = getattr(http, "server", None)
            self.set_cookie = getattr(http, "set_cookie", None)
            # Common fields
            self.connection = getattr(http, "connection", None)
            self.cache_control = getattr(http, "cache_control", None)


def read_http_traffic(path):
    pcap = pyshark.FileCapture(path)
    http_flows = []

    for packet in pcap:
        if hasattr(packet, "http"):
            print("hhhhh")
            flow = HttpFlow()
            flow.add_http_info(packet)
            http_flows.append(flow)

    return http_flows


def print_flow_features(flows):
    for i, flow in enumerate(flows, 1):
        print(f"\nFlow {i}:")
        print("IP Layer:")
        for attr, value in vars(IpFlow()).items():
            if hasattr(flow, attr) and getattr(flow, attr) is not None:
                print(f"  {attr}: {getattr(flow, attr)}")

        print("TCP Layer:")
        for attr, value in vars(TcpFlow()).items():
            if (
                attr not in vars(IpFlow())
                and hasattr(flow, attr)
                and getattr(flow, attr) is not None
            ):
                print(f"  {attr}: {getattr(flow, attr)}")

        print("HTTP Layer:")
        for attr, value in vars(HttpFlow()).items():
            if (
                attr not in vars(TcpFlow())
                and hasattr(flow, attr)
                and getattr(flow, attr) is not None
            ):
                print(f"  {attr}: {getattr(flow, attr)}")


if __name__ == "__main__":
    print("analyzing http traffic...")
    http_flows = read_http_traffic("test.pcap")
    print_flow_features(http_flows)
