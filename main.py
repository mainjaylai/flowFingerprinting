import pyshark
import reader
if __name__ == "__main__":
    print("Hello, world!")
    reader = reader.Reader()
    print(reader.tshark_version())

    # cap = pyshark.FileCapture('tcpdump_output.pcap')
    # for packet in cap:
    #     try:
    #         # 打印每个包的基本信息
    #         print(packet)
    #         break
    #     except AttributeError:
    #         # 如果包中缺少某些信息，跳过
    #         pass


