#ifndef ARP_H
#define ARP_H

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

EthArpPacket makeArpPacket(Mac sMac, Ip sIp, Ip dIp);
bool checkArpReply(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
Mac getSenderMac(const u_char* pkt_data);
EthArpPacket makeArpSpoofingPacket(Mac senderMac, Mac myMac, Ip targetIp, Ip senderIp);
#endif // ARP_H
