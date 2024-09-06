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

class IcmpFlow:
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.version = None
        self.ttl = None
        self.protocol = None
        self.type = None
        self.code = None
        self.checksum = None
        self.id = None
        self.seq = None
        self.request_in = None
        self.response_to = None
        self.time = None
        self.data_len = None
        self.data = None

    def add_icmp_info(self, packet):
        if hasattr(packet, "ip"):
            ip = packet.ip
            self.src_ip = ip.src
            self.dst_ip = ip.dst
            self.version = ip.version
            self.ttl = ip.ttl
            self.protocol = ip.proto

        if hasattr(packet, "icmp"):
            icmp = packet.icmp
            self.type = getattr(icmp, "type", None)
            self.code = getattr(icmp, "code", None)
            self.checksum = getattr(icmp, "checksum", None)
            self.id = getattr(icmp, "id", None)
            self.seq = getattr(icmp, "seq", None)
            self.request_in = getattr(icmp, "request_in", None)
            self.response_to = getattr(icmp, "response_to", None)
            self.time = getattr(icmp, "time", None)
            self.data_len = getattr(icmp, "data_len", None)
            self.data = getattr(icmp, "data", None)