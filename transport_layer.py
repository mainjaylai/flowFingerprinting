from network_layer import IpFlow

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

            if hasattr(packet.tcp, "options_mss"):
                self.mss = packet.tcp.options_mss
            if hasattr(packet.tcp, "options_wscale"):
                self.window_scale = packet.tcp.options_wscale
            if hasattr(packet.tcp, "options_sack_perm"):
                self.sack_permitted = True

class UdpFlow(IpFlow):
    def __init__(self):
        super().__init__()
        self.src_port = None
        self.dst_port = None
        self.length = None
        self.checksum = None
        self.stream = None
        self.payload = None
        self.time_delta = None
        self.time_relative = None
        self.application_protocol = None

    def add_udp_info(self, packet):
        super().add_ip_info(packet)
        if hasattr(packet, "udp"):
            udp = packet.udp
            self.src_port = udp.srcport
            self.dst_port = udp.dstport
            self.length = udp.length
            self.checksum = udp.checksum
            self.stream = getattr(udp, "stream", None)
            self.payload = getattr(udp, "payload", None)
            self.time_delta = getattr(packet, "time_delta", None)
            self.time_relative = getattr(packet, "time_relative", None)

        if hasattr(packet, "dns"):
            self.application_protocol = "DNS"
        elif hasattr(packet, "dhcp"):
            self.application_protocol = "DHCP"
        elif hasattr(packet, "ntp"):
            self.application_protocol = "NTP"
        elif hasattr(packet, "snmp"):
            self.application_protocol = "SNMP"
        else:
            self.application_protocol = "Unknown"