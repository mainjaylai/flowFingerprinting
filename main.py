from reader import Reader
from feature_processor import FeatureProcessor
from unsupervised_trainer import UnsupervisedTrainer
from rule_based_grouping import RuleBasedGrouping, time_based_grouping, frequency_based_grouping

def main():
    # 1. 读取 pcap 文件
    reader = Reader(verbose=True)
    pcap_file = "test.pcap"  # 请替换为您的 pcap 文件路径
    flows = reader.read_pcap(pcap_file)
    print(f"读取了 {len(flows)} 条流量记录")

    # 2. 处理特征
    processor = FeatureProcessor()
    features, flow_info = processor.process_features(flows, 'all')
    print(f"提取了 {features.shape[1]} 个特征")

    # 3. 无监督学习
    trainer = UnsupervisedTrainer()
    model_results = trainer.train_all_models(features, flow_info)
    similar_flows = trainer.find_similar_flows(model_results)

    # 打印无监督学习结果
    print("\n无监督学习结果:")
    for model_name, clusters in similar_flows.items():
        print(f"\n{model_name} 结果:")
        for cluster_id, info in clusters.items():
            print(f"  簇 {cluster_id}:")
            print(f"    最常见目标 IP: {info['most_common_dst_ip']}")
            print(f"    最常见目标端口: {info['most_common_dst_port']}")
            print(f"    最常见协议: {info['most_common_protocol']}")
            print(f"    流量数量: {info['flow_count']}")
            print(f"    唯一目标 IP 数: {info['unique_dst_ips']}")
            print(f"    唯一目标端口数: {info['unique_dst_ports']}")
            print(f"    唯一协议数: {info['unique_protocols']}")

    # 4. 基于规则的分组
    rule_grouper = RuleBasedGrouping()
    rule_grouper.group_flows(flows)
    rule_based_results = rule_grouper.find_similar_flows()

    print("\n基于规则的分组结果:")
    rule_grouper.print_results(rule_based_results)

    # 5. 基于时间的分组
    time_groups = time_based_grouping(flows)
    print("\n基于时间的分组结果:")
    for time_key, group in time_groups.items():
        print(f"时间窗口 {time_key}: {len(group)} 条流量")

    # 6. 基于频率的分组
    frequent_flows = frequency_based_grouping(flows)
    print("\n基于频率的分组结果:")
    for key, count in frequent_flows.items():
        print(f"流量 {key}: 出现 {count} 次")

if __name__ == "__main__":
    main()

