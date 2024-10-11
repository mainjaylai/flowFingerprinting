import pyshark
# 捕获文件的路径或网络接口
capture = pyshark.FileCapture('C:\\Users\\Administrator\\Desktop\\capture.pcap')

target_ip = '192.168.1.114'

macs = set()

for packet in capture:
    try:
        # 检查是否有 IP 层
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # 提取 MAC 地址
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst
            
            # 检查是否与目标 IP 地址匹配
            if src_ip == target_ip:
                print(f'Source IP: {src_ip}, Source MAC: {src_mac}')
                macs.add(src_mac)
            elif dst_ip == target_ip:
                print(f'Destination IP: {dst_ip}, Destination MAC: {dst_mac}')
                macs.add(dst_mac)
    except AttributeError:
        # 有些数据包可能没有以太网层或 IP 层
        continue

print(macs)