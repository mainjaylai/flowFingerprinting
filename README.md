# 网络流量分析工具

这个项目是一个用于分析网络流量的工具，它可以读取 pcap 文件，提取各种协议的特征，并使用多种方法对流量进行分类和分组。

## 功能特点

1. 支持多种网络协议的流量分析，包括 IP, TCP, UDP, HTTP, SMTP, FTP, 和 ICMP。
2. 使用 pyshark 和 cicflowmeter 提取流量特征。
3. 提供无监督学习方法对流量进行聚类分析。
4. 实现了基于规则的流量分组方法。
5. 支持基于时间和频率的流量分组。

## 项目结构

- `main.py`: 主程序入口，orchestrates 整个分析流程。
- `reader.py`: 负责读取 pcap 文件并提取初始特征。
- `feature_processor.py`: 处理和转换提取的特征。
- `unsupervised_trainer.py`: 实现无监督学习方法。
- `rule_based_grouping.py`: 实现基于规则的分组方法。
- `flows.py`: 定义了各种协议的 Flow 类。
- `network_layer.py`, `transport_layer.py`, `application_layer.py`: 定义了不同网络层的基础类。

## 安装依赖

在运行此项目之前，请确保安装了所有必要的依赖：

```bash
pip install pyshark cicflowmeter sklearn numpy hdbscan umap-learn
```

## 使用方法

1. 将您的 pcap 文件放在项目目录中。
2. 在 `main.py` 中修改 pcap 文件的路径：

```python
pcap_file = "your_pcap_file.pcap"
```

3. 运行 `main.py`：

```bash
python main.py
```

## 输出结果

程序将输出以下信息：

1. 读取的流量记录数量和提取的特征数量。
2. 无监督学习的聚类结果，包括每个簇的常见特征。
3. 基于规则的分组结果。
4. 基于时间的分组结果。
5. 基于频率的分组结果。

## 自定义和扩展

- 要添加新的协议支持，可以在 `flows.py` 中定义新的 Flow 类。
- 要修改特征提取方法，可以编辑 `feature_processor.py`。
- 要添加新的聚类算法，可以在 `unsupervised_trainer.py` 中的 `models` 字典中添加。

## 注意事项

- 此工具设计用于分析 NAT 网络环境下的流量，因此主要关注目标 IP 和端口，而不是源 IP。
- 确保您有足够的计算资源来处理大型 pcap 文件，特别是在使用无监督学习方法时。

## 贡献

欢迎提交 issues 和 pull requests 来帮助改进这个项目。
