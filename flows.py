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
        self.headers = {}  # 添加一个字典来存储所有HTTP头

    def add_http_info(self, packet):
        super().add_tcp_info(packet)
        if hasattr(packet, "http"):
            http = packet.http
            # 使用一个循环来获取所有HTTP字段
            for field in http.field_names:
                value = getattr(http, field)
                if value:
                    self.headers[field] = value
            
            # 更新特定属性
            self.method = self.headers.get("request_method")
            self.uri = self.headers.get("request_uri")
            self.version = self.headers.get("request_version")
            self.status_code = self.headers.get("response_code")
            # ... 其他属性的更新 ...


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

        # 提取可能的应用层协议信息
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


class SmtpFlow(TcpFlow):
    def __init__(self):
        super().__init__()
        self.command = None
        self.response_code = None
        self.response_parameter = None
        self.request_parameter = None
        self.data = None
        self.ehlo_domain = None
        self.auth_mechanism = None
        self.mail_from = None
        self.rcpt_to = []
        self.subject = None
        self.content_type = None
        self.headers = {}

    def add_smtp_info(self, packet):
        super().add_tcp_info(packet)
        if hasattr(packet, "smtp"):
            smtp = packet.smtp
            self.command = getattr(smtp, "command", None)
            self.response_code = getattr(smtp, "response_code", None)
            self.response_parameter = getattr(smtp, "response_parameter", None)
            self.request_parameter = getattr(smtp, "request_parameter", None)
            self.data = getattr(smtp, "data", None)
            
            # 提取更多SMTP特定信息
            if hasattr(smtp, "ehlo_domain"):
                self.ehlo_domain = smtp.ehlo_domain
            if hasattr(smtp, "auth_mechanism"):
                self.auth_mechanism = smtp.auth_mechanism
            if hasattr(smtp, "mail_from"):
                self.mail_from = smtp.mail_from
            if hasattr(smtp, "rcpt_to"):
                self.rcpt_to.append(smtp.rcpt_to)
            
            # 提取邮件头信息
            if hasattr(smtp, "mail_subject"):
                self.subject = smtp.mail_subject
            if hasattr(smtp, "mail_content_type"):
                self.content_type = smtp.mail_content_type
            
            # 存储所有可用的SMTP字段
            for field in smtp.field_names:
                value = getattr(smtp, field)
                if value:
                    self.headers[field] = value


class FtpFlow(TcpFlow):
    def __init__(self):
        super().__init__()
        self.command = None
        self.response_code = None
        self.response_arg = None
        self.request_arg = None
        self.file_data = None
        self.file_name = None
        self.file_size = None
        self.current_working_directory = None
        self.data_port = None
        self.passive_port = None
        self.headers = {}

    def add_ftp_info(self, packet):
        super().add_tcp_info(packet)
        if hasattr(packet, "ftp"):
            ftp = packet.ftp
            self.command = getattr(ftp, "command", None)
            self.response_code = getattr(ftp, "response_code", None)
            self.response_arg = getattr(ftp, "response_arg", None)
            self.request_arg = getattr(ftp, "request_arg", None)
            
            # 提取更多FTP特定信息
            if hasattr(ftp, "file_data"):
                self.file_data = ftp.file_data
            if hasattr(ftp, "file_name"):
                self.file_name = ftp.file_name
            if hasattr(ftp, "file_size"):
                self.file_size = ftp.file_size
            if hasattr(ftp, "current_working_directory"):
                self.current_working_directory = ftp.current_working_directory
            if hasattr(ftp, "data_port"):
                self.data_port = ftp.data_port
            if hasattr(ftp, "passive_port"):
                self.passive_port = ftp.passive_port
            
            # 存储所有可用的FTP字段
            for field in ftp.field_names:
                value = getattr(ftp, field)
                if value:
                    self.headers[field] = value


class IcmpFlow(object):
    def __init__(self):
        # IP层属性
        self.src_ip = None
        self.dst_ip = None
        self.version = None
        self.ttl = None
        self.protocol = None
        
        # ICMP特有属性
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


def read_http_traffic(path):
    pcap = pyshark.FileCapture(path, display_filter="http")
    http_flows = []

    for packet in pcap:
        if hasattr(packet, "http"):
            flow = HttpFlow()
            flow.add_http_info(packet)
            http_flows.append(flow)

    pcap.close()
    return http_flows


def print_flow_features(flows):
    for i, flow in enumerate(flows, 1):
        print(f"\n流 {i}:")
        print("IP 层:")
        for attr, value in vars(IpFlow()).items():
            if hasattr(flow, attr) and getattr(flow, attr) is not None:
                print(f"  {attr}: {getattr(flow, attr)}")

        if isinstance(flow, TcpFlow):
            print("TCP 层:")
            for attr, value in vars(TcpFlow()).items():
                if (
                    attr not in vars(IpFlow())
                    and hasattr(flow, attr)
                    and getattr(flow, attr) is not None
                ):
                    print(f"  {attr}: {getattr(flow, attr)}")

        if isinstance(flow, HttpFlow):
            print("HTTP 层:")
            for attr, value in flow.headers.items():
                print(f"  {attr}: {value}")
        elif isinstance(flow, SmtpFlow):
            print("SMTP 层:")
            for attr, value in flow.headers.items():
                print(f"  {attr}: {value}")
        elif isinstance(flow, FtpFlow):
            print("FTP 层:")
            for attr, value in flow.headers.items():
                print(f"  {attr}: {value}")
        elif isinstance(flow, UdpFlow):
            print("UDP 层:")
            for attr, value in vars(UdpFlow()).items():
                if (
                    attr not in vars(IpFlow())
                    and hasattr(flow, attr)
                    and getattr(flow, attr) is not None
                ):
                    print(f"  {attr}: {getattr(flow, attr)}")
        elif isinstance(flow, IcmpFlow):
            print("IP 层:")
            for attr in ['src_ip', 'dst_ip', 'version', 'ttl', 'protocol']:
                if hasattr(flow, attr) and getattr(flow, attr) is not None:
                    print(f"  {attr}: {getattr(flow, attr)}")
            
            print("ICMP 层:")
            for attr, value in vars(IcmpFlow()).items():
                if attr not in ['src_ip', 'dst_ip', 'version', 'ttl', 'protocol'] and hasattr(flow, attr) and getattr(flow, attr) is not None:
                    print(f"  {attr}: {getattr(flow, attr)}")


def read_udp_traffic(path):
    pcap = pyshark.FileCapture(path, display_filter="udp")
    udp_flows = []

    for packet in pcap:
        if hasattr(packet, "udp"):
            flow = UdpFlow()
            flow.add_udp_info(packet)
            udp_flows.append(flow)

    pcap.close()
    return udp_flows


def read_smtp_traffic(path):
    pcap = pyshark.FileCapture(path, display_filter="smtp")
    smtp_flows = []

    for packet in pcap:
        if hasattr(packet, "smtp"):
            flow = SmtpFlow()
            flow.add_smtp_info(packet)
            smtp_flows.append(flow)

    pcap.close()
    return smtp_flows


def read_ftp_traffic(path):
    pcap = pyshark.FileCapture(path, display_filter="ftp or ftp-data")
    ftp_flows = []

    for packet in pcap:
        if hasattr(packet, "ftp") or hasattr(packet, "ftp-data"):
            flow = FtpFlow()
            flow.add_ftp_info(packet)
            ftp_flows.append(flow)

    pcap.close()
    return ftp_flows


def read_icmp_traffic(path):
    pcap = pyshark.FileCapture(path, display_filter="icmp")
    icmp_flows = []

    for packet in pcap:
        if hasattr(packet, "icmp"):
            flow = IcmpFlow()
            flow.add_icmp_info(packet)
            icmp_flows.append(flow)

    pcap.close()
    return icmp_flows


# 在 main 函数中使用
if __name__ == "__main__":
    print("分析 UDP 流量...")
    udp_flows = read_udp_traffic("test.pcap")
    print_flow_features(udp_flows)

    print("\n分析 SMTP 流量...")
    smtp_flows = read_smtp_traffic("test.pcap")
    print_flow_features(smtp_flows)

    print("\n分析 FTP 流量...")
    ftp_flows = read_ftp_traffic("test.pcap")
    print_flow_features(ftp_flows)

    print("\n分析 ICMP 流量...")
    icmp_flows = read_icmp_traffic("test.pcap")
    print_flow_features(icmp_flows)
