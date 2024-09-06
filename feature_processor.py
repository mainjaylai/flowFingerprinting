import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import ipaddress

class FeatureProcessor:
    def __init__(self):
        self.preprocessor = None

    def process_features(self, flows, protocol):
        """
        根据不同协议处理特征
        
        Args:
            flows (list): Flow对象列表
            protocol (str): 协议类型 ('ip', 'tcp', 'udp', 'http', 'smtp', 'ftp', 'icmp')
        
        Returns:
            np.array: 处理后的特征数组
        """
        if protocol == 'ip':
            return self.process_ip_features(flows)
        elif protocol == 'tcp':
            return self.process_tcp_features(flows)
        elif protocol == 'udp':
            return self.process_udp_features(flows)
        elif protocol == 'http':
            return self.process_http_features(flows)
        elif protocol == 'smtp':
            return self.process_smtp_features(flows)
        elif protocol == 'ftp':
            return self.process_ftp_features(flows)
        elif protocol == 'icmp':
            return self.process_icmp_features(flows)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def process_ip_features(self, flows):
        features = []
        for flow in flows:
            feature = [
                self.encode_ip(flow.src_ip),
                self.encode_ip(flow.dst_ip),
                flow.protocol,
                flow.ttl,
                flow.total_length,
                flow.identification,
                flow.flags,
                flow.fragment_offset,
                flow.header_length
            ]
            features.append(feature)
        return np.array(features)

    def process_tcp_features(self, flows):
        features = []
        for flow in flows:
            feature = [
                self.encode_ip(flow.src_ip),
                self.encode_ip(flow.dst_ip),
                flow.src_port,
                flow.dst_port,
                flow.seq_num,
                flow.ack_num,
                flow.window_size,
                flow.tcp_flags
            ]
            features.append(feature)
        return np.array(features)

    def process_udp_features(self, flows):
        features = []
        for flow in flows:
            feature = [
                self.encode_ip(flow.src_ip),
                self.encode_ip(flow.dst_ip),
                flow.src_port,
                flow.dst_port,
                flow.length,
                flow.checksum
            ]
            features.append(feature)
        return np.array(features)

    def process_http_features(self, flows):
        features = []
        for flow in flows:
            feature = [
                self.encode_ip(flow.src_ip),
                self.encode_ip(flow.dst_ip),
                flow.src_port,
                flow.dst_port,
                self.encode_method(flow.method),
                self.encode_uri(flow.uri),
                flow.version,
                flow.status_code,
                len(flow.headers)
            ]
            features.append(feature)
        return np.array(features)

    def process_smtp_features(self, flows):
        features = []
        for flow in flows:
            feature = [
                self.encode_ip(flow.src_ip),
                self.encode_ip(flow.dst_ip),
                flow.src_port,
                flow.dst_port,
                self.encode_command(flow.command),
                flow.response_code,
                self.encode_email(flow.mail_from),
                len(flow.rcpt_to),
                len(flow.headers)
            ]
            features.append(feature)
        return np.array(features)

    def process_ftp_features(self, flows):
        features = []
        for flow in flows:
            feature = [
                self.encode_ip(flow.src_ip),
                self.encode_ip(flow.dst_ip),
                flow.src_port,
                flow.dst_port,
                self.encode_command(flow.command),
                flow.response_code,
                self.encode_filename(flow.file_name),
                flow.file_size
            ]
            features.append(feature)
        return np.array(features)

    def process_icmp_features(self, flows):
        features = []
        for flow in flows:
            feature = [
                self.encode_ip(flow.src_ip),
                self.encode_ip(flow.dst_ip),
                flow.type,
                flow.code,
                flow.checksum,
                flow.id,
                flow.seq
            ]
            features.append(feature)
        return np.array(features)

    def encode_ip(self, ip):
        try:
            return int(ipaddress.ip_address(ip))
        except:
            return 0

    def encode_method(self, method):
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        return methods.index(method) if method in methods else len(methods)

    def encode_uri(self, uri):
        return hash(uri) % 1000000  # 使用哈希值并取模，以限制特征的范围

    def encode_command(self, command):
        return hash(command) % 1000000 if command else 0

    def encode_email(self, email):
        return hash(email) % 1000000 if email else 0

    def encode_filename(self, filename):
        return hash(filename) % 1000000 if filename else 0

    def fit_transform(self, X):
        numeric_features = list(range(X.shape[1]))
        numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])

        self.preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_features)
            ])

        return self.preprocessor.fit_transform(X)

    def remove_correlated_features(self, X, threshold=0.95):
        corr_matrix = np.abs(np.corrcoef(X.T))
        upper = np.triu(corr_matrix, k=1)
        to_drop = [column for column in range(len(upper.T)) if any(upper[:, column] > threshold)]
        return np.delete(X, to_drop, axis=1)

    def remove_low_variance_features(self, X, threshold=0.1):
        variances = np.var(X, axis=0)
        return X[:, variances > threshold]

if __name__ == "__main__":
    from reader import Reader
    
    reader = Reader(verbose=True)
    flows = reader.read_pcap("test.pcap")
    
    processor = FeatureProcessor()
    
    # 处理不同协议的特征
    http_features = processor.process_features([f for f in flows if isinstance(f, HttpFlow)], 'http')
    tcp_features = processor.process_features([f for f in flows if isinstance(f, TcpFlow)], 'tcp')
    udp_features = processor.process_features([f for f in flows if isinstance(f, UdpFlow)], 'udp')
    
    # 对特征进行进一步处理
    http_processed = processor.fit_transform(http_features)
    http_processed = processor.remove_correlated_features(http_processed)
    http_processed = processor.remove_low_variance_features(http_processed)
    
    print(f"HTTP特征数量: {http_processed.shape[1]}")
    print(f"TCP特征数量: {tcp_features.shape[1]}")
    print(f"UDP特征数量: {udp_features.shape[1]}")