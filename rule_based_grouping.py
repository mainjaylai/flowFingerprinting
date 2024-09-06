from collections import defaultdict
from reader import Reader
from feature_processor import FeatureProcessor

class RuleBasedGrouping:
    def __init__(self):
        self.groups = defaultdict(list)

    def group_flows(self, flows):
        for flow in flows:
            key = self.generate_group_key(flow)
            self.groups[key].append(flow)

    def generate_group_key(self, flow):
        # 这里可以根据需要调整分组的规则
        return (flow.dst_ip, flow.dst_port, flow.protocol)

    def find_similar_flows(self):
        similar_flows = {}
        for key, flows in self.groups.items():
            dst_ip, dst_port, protocol = key
            similar_flows[key] = {
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "flow_count": len(flows),
                "unique_src_ips": len(set(flow.src_ip for flow in flows)),
                "avg_packet_size": sum(flow.total_length for flow in flows) / len(flows),
                "avg_duration": sum(flow.duration for flow in flows if hasattr(flow, 'duration')) / len(flows),
            }
        return similar_flows

    def print_results(self, similar_flows):
        for key, info in similar_flows.items():
            print(f"\nGroup: {key}")
            print(f"  Destination IP: {info['dst_ip']}")
            print(f"  Destination Port: {info['dst_port']}")
            print(f"  Protocol: {info['protocol']}")
            print(f"  Flow Count: {info['flow_count']}")
            print(f"  Unique Source IPs: {info['unique_src_ips']}")
            print(f"  Average Packet Size: {info['avg_packet_size']:.2f}")
            print(f"  Average Duration: {info['avg_duration']:.2f}")

def time_based_grouping(flows, time_window=60):
    time_groups = defaultdict(list)
    for flow in flows:
        time_key = int(flow.timestamp) // time_window
        time_groups[time_key].append(flow)
    return time_groups

def frequency_based_grouping(flows, threshold=10):
    frequency = defaultdict(int)
    for flow in flows:
        key = (flow.dst_ip, flow.dst_port, flow.protocol)
        frequency[key] += 1
    
    frequent_flows = {key: flows for key, flows in frequency.items() if flows >= threshold}
    return frequent_flows

if __name__ == "__main__":
    # 读取数据
    reader = Reader(verbose=True)
    flows = reader.read_pcap("test.pcap")

    # 处理特征
    processor = FeatureProcessor()
    processed_flows = processor.process_features(flows, 'all')

    # 基于规则的分组
    grouper = RuleBasedGrouping()
    grouper.group_flows(processed_flows)
    similar_flows = grouper.find_similar_flows()
    grouper.print_results(similar_flows)

    # 基于时间的分组
    time_groups = time_based_grouping(processed_flows)
    print("\nTime-based grouping:")
    for time_key, group in time_groups.items():
        print(f"Time window {time_key}: {len(group)} flows")

    # 基于频率的分组
    frequent_flows = frequency_based_grouping(processed_flows)
    print("\nFrequency-based grouping:")
    for key, count in frequent_flows.items():
        print(f"Flow {key}: {count} occurrences")