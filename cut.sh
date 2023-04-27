mkdir -p attack_set
# editcap -c 200000 dataset/cut20200610.pcapng train_set/output.pcapng
# editcap -r dataset/2020.pcapng dataset/benign_small.pcapng 1-100000

cp dataset/BruteForce-Web.pcap attack_set/BruteForce-Web.pcap
cp dataset/BruteForce-XSS.pcap attack_set/BruteForce-XSS.pcap
cp dataset/fuzzscan.pcap attack_set/fuzzscan.pcapng
cp dataset/infiltration.pcap attack_set/infiltration.pcapng
cp dataset/osscan.pcap attack_set/osscan.pcap
cp dataset/SQL_Injection.pcap attack_set/SQL_Injection.pcap
# cp dataset/ssldosA10only.pcap attack_set/ssldosA10only.pcap
cp dataset/ssldosA.pcap attack_set/ssldosA.pcap

# editcap -r dataset_lite/mirai.pcapng attack_set/mirai-attack.pcapng 70000-764137

editcap -r dataset/HOIC.pcap attack_set/HOIC_small.pcapng 1-100000
editcap -r dataset/LDoS.pcap attack_set/LDoS_small.pcapng 1-100000
editcap -r dataset/LOIC_UDP.pcap attack_set/LOIC_UDP_small.pcapng 1-100000
# editcap -r dataset/SYNDoS.pcap attack_set/SYNDoS_small.pcapng 1-100000
editcap -r dataset/SYNDoS.pcap attack_set/SYNDoS_small.pcapng 600000-800000