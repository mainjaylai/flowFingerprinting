import numpy as np
from sklearn.cluster import KMeans, DBSCAN, AgglomerativeClustering
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from hdbscan import HDBSCAN
from collections import defaultdict
from feature_processor import FeatureProcessor
from reader import Reader


class UnsupervisedTrainer:
    def __init__(self, n_clusters=5):
        self.n_clusters = n_clusters
        self.models = {
            "KMeans": KMeans(n_clusters=self.n_clusters),
            "DBSCAN": DBSCAN(eps=0.5, min_samples=5),
            "AgglomerativeClustering": AgglomerativeClustering(
                n_clusters=self.n_clusters
            ),
            "GaussianMixture": GaussianMixture(n_components=self.n_clusters),
            "HDBSCAN": HDBSCAN(min_cluster_size=5),
        }

    def preprocess_data(self, X):
        scaler = StandardScaler()
        return scaler.fit_transform(X)

    def train_all_models(self, X, flow_info):
        X_preprocessed = self.preprocess_data(X)
        results = {}
        for name, model in self.models.items():
            print(f"Training {name}...")
            model.fit(X_preprocessed)
            if hasattr(model, "labels_"):
                labels = model.labels_
            elif hasattr(model, "predict"):
                labels = model.predict(X_preprocessed)
            else:
                raise AttributeError(
                    f"{name} has no labels_ attribute or predict method"
                )

            silhouette = (
                silhouette_score(X_preprocessed, labels)
                if len(np.unique(labels)) > 1
                else 0
            )
            results[name] = {
                "model": model,
                "labels": labels,
                "silhouette_score": silhouette,
                "clusters": self.get_clusters(labels, flow_info),
            }
            print(f"{name} Silhouette Score: {silhouette}")
        return results

    def get_clusters(self, labels, flow_info):
        clusters = defaultdict(list)
        for label, info in zip(labels, flow_info):
            clusters[label].append(info)
        return clusters

    def find_similar_flows(self, results):
        similar_flows = {}
        for model_name, result in results.items():
            similar_flows[model_name] = {}
            for cluster_id, flows in result["clusters"].items():
                dst_ip_counts = defaultdict(int)
                dst_port_counts = defaultdict(int)
                protocol_counts = defaultdict(int)
                for flow in flows:
                    dst_ip_counts[flow["dst_ip"]] += 1
                    dst_port_counts[flow["dst_port"]] += 1
                    protocol_counts[flow["protocol"]] += 1

                most_common_dst_ip = max(dst_ip_counts, key=dst_ip_counts.get)
                most_common_dst_port = max(dst_port_counts, key=dst_port_counts.get)
                most_common_protocol = max(protocol_counts, key=protocol_counts.get)

                similar_flows[model_name][cluster_id] = {
                    "most_common_dst_ip": most_common_dst_ip,
                    "most_common_dst_port": most_common_dst_port,
                    "most_common_protocol": most_common_protocol,
                    "flow_count": len(flows),
                    "unique_dst_ips": len(set(flow["dst_ip"] for flow in flows)),
                    "unique_dst_ports": len(set(flow["dst_port"] for flow in flows)),
                    "unique_protocols": len(set(flow["protocol"] for flow in flows)),
                }
        return similar_flows

    def reduce_dimensionality(self, X):
        X_preprocessed = self.preprocess_data(X)
        results = {}
        for name, model in self.dimensionality_reduction.items():
            print(f"Applying {name}...")
            X_reduced = model.fit_transform(X_preprocessed)
            results[name] = X_reduced
        return results


if __name__ == "__main__":
    # 读取数据
    reader = Reader(verbose=True)
    flows = reader.read_pcap("test.pcap")

    # 处理特征
    processor = FeatureProcessor()
    features, flow_info = processor.process_features(
        flows, "all"
    )  # 假设我们添加了一个'all'选项来处理所有协议

    # 创建并训练无监督模型
    trainer = UnsupervisedTrainer()
    model_results = trainer.train_all_models(features, flow_info)

    # 找出可能来自同一服务器的流量
    similar_flows = trainer.find_similar_flows(model_results)

    # 打印结果
    for model_name, clusters in similar_flows.items():
        print(f"\n{model_name} Results:")
        for cluster_id, info in clusters.items():
            print(f"  Cluster {cluster_id}:")
            print(f"    Most common destination IP: {info['most_common_dst_ip']}")
            print(f"    Most common destination port: {info['most_common_dst_port']}")
            print(f"    Most common protocol: {info['most_common_protocol']}")
            print(f"    Flow count: {info['flow_count']}")
            print(f"    Unique destination IPs: {info['unique_dst_ips']}")
            print(f"    Unique destination ports: {info['unique_dst_ports']}")
            print(f"    Unique protocols: {info['unique_protocols']}")

    print("\nDimensionality Reduction Results:")
    for name, result in reduced_features.items():
        print(f"{name} shape: {result.shape}")
