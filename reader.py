import re
from subprocess import PIPE, Popen
import pyshark
import numpy as np
from cicflowmeter.flow_session import generate_session_class
from cicflowmeter.features.context.packet_direction import PacketDirection
from cicflowmeter.features.context.packet_flow_key import get_packet_flow_key
from flows import IpFlow, TcpFlow, UdpFlow, HttpFlow, SmtpFlow, FtpFlow, IcmpFlow

class Reader(object):
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.flow_session = generate_session_class()

    def tshark_version(self):
        command = ["tshark", "--version"]
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        out, err = process.communicate()

        if err:
            raise ValueError(f"Exception in tshark version check: '{err}'")

        regex = re.compile(r"TShark .*(\d+\.\d+\.\d+) ")
        out = out.decode("utf-8")
        version = regex.search(out).group(1)

        return version

    def read_pcap(self, path: str):
        """读取pcap文件并提取所有协议的特征

        Args:
            path (str): pcap文件路径

        Returns:
            np.array: 包含所有流量特征的特征集
        """
        if self.verbose:
            print(f"正在读取 {path}")

        pcap = pyshark.FileCapture(path)
        flow_array = []
        cic_flows = self.flow_session.process_pcap(path)

        for packet in pcap:
            flow = self.extract_flow(packet)
            if flow:
                flow_array.append(flow)

        pcap.close()
        return self.merge_features(flow_array, cic_flows)

    def extract_flow(self, packet):
        """从数据包中提取流量特征

        Args:
            packet: pyshark数据包对象

        Returns:
            Flow对象或None
        """
        if hasattr(packet, 'ip'):
            if hasattr(packet, 'icmp'):
                flow = IcmpFlow()
                flow.add_icmp_info(packet)
            elif hasattr(packet, 'tcp'):
                if hasattr(packet, 'http'):
                    flow = HttpFlow()
                    flow.add_http_info(packet)
                elif hasattr(packet, 'smtp'):
                    flow = SmtpFlow()
                    flow.add_smtp_info(packet)
                elif hasattr(packet, 'ftp') or hasattr(packet, 'ftp-data'):
                    flow = FtpFlow()
                    flow.add_ftp_info(packet)
                else:
                    flow = TcpFlow()
                    flow.add_tcp_info(packet)
            elif hasattr(packet, 'udp'):
                flow = UdpFlow()
                flow.add_udp_info(packet)
            else:
                flow = IpFlow()
                flow.add_ip_info(packet)
            return flow
        return None

    def merge_features(self, flow_array, cic_flows):
        """合并我们提取的特征和cicflowmeter提取的特征

        Args:
            flow_array (list): 我们提取的Flow对象列表
            cic_flows (dict): cicflowmeter提取的流量特征字典

        Returns:
            np.array: 合并后的特征集
        """
        merged_features = []

        for flow in flow_array:
            flow_key = f"{flow.src_ip}:{flow.src_port}-{flow.dst_ip}:{flow.dst_port}"
            cic_flow = cic_flows.get(flow_key)

            if cic_flow:
                # 提取cicflowmeter特征
                cic_features = [
                    cic_flow.duration,
                    cic_flow.total_fwd_packets,
                    cic_flow.total_bwd_packets,
                    cic_flow.total_length_of_fwd_packets,
                    cic_flow.total_length_of_bwd_packets,
                    cic_flow.fwd_packet_length_max,
                    cic_flow.fwd_packet_length_min,
                    cic_flow.fwd_packet_length_mean,
                    cic_flow.fwd_packet_length_std,
                    cic_flow.bwd_packet_length_max,
                    cic_flow.bwd_packet_length_min,
                    cic_flow.bwd_packet_length_mean,
                    cic_flow.bwd_packet_length_std,
                    cic_flow.flow_bytes_s,
                    cic_flow.flow_packets_s,
                    cic_flow.flow_iat_mean,
                    cic_flow.flow_iat_std,
                    cic_flow.flow_iat_max,
                    cic_flow.flow_iat_min,
                    cic_flow.fwd_iat_total,
                    cic_flow.fwd_iat_mean,
                    cic_flow.fwd_iat_std,
                    cic_flow.fwd_iat_max,
                    cic_flow.fwd_iat_min,
                    cic_flow.bwd_iat_total,
                    cic_flow.bwd_iat_mean,
                    cic_flow.bwd_iat_std,
                    cic_flow.bwd_iat_max,
                    cic_flow.bwd_iat_min,
                    cic_flow.fwd_psh_flags,
                    cic_flow.bwd_psh_flags,
                    cic_flow.fwd_urg_flags,
                    cic_flow.bwd_urg_flags,
                    cic_flow.fwd_header_length,
                    cic_flow.bwd_header_length,
                    cic_flow.down_up_ratio,
                    cic_flow.average_packet_size,
                    cic_flow.avg_fwd_segment_size,
                    cic_flow.avg_bwd_segment_size,
                    cic_flow.fwd_avg_bytes_bulk,
                    cic_flow.fwd_avg_packets_bulk,
                    cic_flow.bwd_avg_bytes_bulk,
                    cic_flow.bwd_avg_packets_bulk,
                    cic_flow.subflow_fwd_packets,
                    cic_flow.subflow_bwd_packets,
                    cic_flow.init_win_bytes_forward,
                    cic_flow.init_win_bytes_backward,
                    cic_flow.act_data_pkt_fwd,
                    cic_flow.min_seg_size_forward,
                ]

                # 提取应用层特征
                app_features = self.extract_app_features(flow)

                # 合并特征
                merged_features.append(cic_features + app_features)

        return np.array(merged_features)

    def extract_app_features(self, flow):
        """提取应用层特征

        Args:
            flow (Flow): Flow对象

        Returns:
            list: 应用层特征列表
        """
        app_features = []

        if isinstance(flow, HttpFlow):
            app_features = [
                flow.method,
                flow.uri,
                flow.version,
                flow.status_code,
                len(flow.headers)
            ]
        elif isinstance(flow, SmtpFlow):
            app_features = [
                flow.command,
                flow.response_code,
                flow.mail_from,
                len(flow.rcpt_to),
                len(flow.headers)
            ]
        elif isinstance(flow, FtpFlow):
            app_features = [
                flow.command,
                flow.response_code,
                flow.file_name,
                flow.file_size,
                flow.data_port
            ]
        elif isinstance(flow, IcmpFlow):
            app_features = [
                flow.type,
                flow.code,
                flow.checksum,
                flow.id,
                flow.seq
            ]

        # 将非数值特征转换为数值
        app_features = [hash(str(feature)) if not isinstance(feature, (int, float)) else feature for feature in app_features]

        return app_features

    def print_flow_features(self, feature_array):
        """打印特征集

        Args:
            feature_array (np.array): 特征集
        """
        for i, features in enumerate(feature_array):
            print(f"\n流 {i + 1}:")
            for j, feature in enumerate(features):
                print(f"  特征 {j + 1}: {feature}")

if __name__ == "__main__":
    reader = Reader(verbose=True)
    feature_array = reader.read_pcap("test.pcap")
    reader.print_flow_features(feature_array)
