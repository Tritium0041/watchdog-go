package archive

import (
	"fmt"
	"log"
	"strings"
	"time"
	"watchdog-go/src"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func listenPackets() {
	device := "eth0" // 设置要监听的网络设备，如网卡接口名

	handle, err := pcap.OpenLive(device, 65536, true, 100*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// 解析数据包的各层协议
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			ethPacket, _ := ethLayer.(*layers.Ethernet)

			if ethPacket.EthernetType == layers.EthernetTypeIPv4 {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					ipPacket, _ := ipLayer.(*layers.IPv4)

					if ipPacket.Protocol == layers.IPProtocolTCP {
						tcpLayer := packet.Layer(layers.LayerTypeTCP)
						if tcpLayer != nil {
							tcpPacket, _ := tcpLayer.(*layers.TCP)

							// 检查是否为 HTTP 流量
							if tcpPacket.DstPort == layers.TCPPort(80) || tcpPacket.SrcPort == layers.TCPPort(80) {
								applicationLayer := packet.ApplicationLayer()
								if applicationLayer != nil {
									payload := applicationLayer.Payload()

									// 解析 HTTP 报文
									httpData := string(payload)
									if strings.HasPrefix(httpData, "GET") || strings.HasPrefix(httpData, "POST") {
										// 在这里对捕获到的 HTTP 请求进行处理和分析
										fmt.Println(httpData)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func packetclassify(payload string) string {
	if !main.wafsqli(payload) {
		// 检测到 SQL 注入攻击

	}

}
