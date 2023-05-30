mkdir -p cic-ids

# Brute Force - FTP (2017-07-04 9:20 – 10:20 a.m.)
# editcap -A "2017-07-04 09:20:00" -B "2017-07-04 10:20:00" cic-ids2017/Tuesday.pcap cic-ids/BruteForce-FTP.pcapng
# editcap -A "2017-07-04 20:20:00" -B "2017-07-04 21:20:00" cic-ids2017/Tuesday.pcap cic-ids/BruteForce-FTP.pcapng
editcap -A "2017-07-04 20:20:00" -B "2017-07-04 20:22:00" cic-ids2017/Tuesday.pcap cic-ids/BruteForce-FTP.pcapng

# Brute Force - SSH (2017-07-04 14:00 – 15:00 p.m.)
# editcap -A "2017-07-04 14:00:00" -B "2017-07-04 15:00:00" cic-ids2017/Tuesday.pcap cic-ids/BruteForce-SSH.pcapng
# editcap -A "2017-07-05 01:00:00" -B "2017-07-05 02:00:00" cic-ids2017/Tuesday.pcap cic-ids/BruteForce-SSH.pcapng
editcap -A "2017-07-05 01:00:00" -B "2017-07-05 01:06:00" cic-ids2017/Tuesday.pcap cic-ids/BruteForce-SSH.pcapng

# DoS slowloris (9:47 – 10:10 a.m.)
# editcap -A "2017-07-05 09:47:00" -B "2017-07-05 10:10:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Slowloris.pcapng
# editcap -A "2017-07-05 20:47:00" -B "2017-07-05 21:10:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Slowloris.pcapng
editcap -A "2017-07-05 20:47:00" -B "2017-07-05 20:50:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Slowloris.pcapng

# DoS Slowhttptest (10:14 – 10:35 a.m.)
# editcap -A "2017-07-05 10:14:00" -B "2017-07-05 10:35:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Slowhttptest.pcapng
# editcap -A "2017-07-05 21:14:00" -B "2017-07-05 21:35:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Slowhttptest.pcapng
editcap -A "2017-07-05 21:14:00" -B "2017-07-05 21:20:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Slowhttptest.pcapng

# DoS Hulk (10:43 – 11 a.m.)
# editcap -A "2017-07-05 10:43:00" -B "2017-07-05 11:00:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Hulk.pcapng
# editcap -A "2017-07-05 21:43:00" -B "2017-07-05 22:00:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Hulk.pcapng
editcap -A "2017-07-05 21:43:00" -B "2017-07-05 21:45:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-Hulk.pcapng

# DoS GoldenEye (11:10 – 11:23 a.m.)
# editcap -A "2017-07-05 11:10:00" -B "2017-07-05 11:23:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-GoldenEye.pcapng
# editcap -A "2017-07-05 22:10:00" -B "2017-07-05 22:23:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-GoldenEye.pcapng
editcap -A "2017-07-05 22:10:00" -B "2017-07-05 22:14:00" cic-ids2017/Wednesday.pcap cic-ids/DoS-GoldenEye.pcapng

# Heartbleed Port 444 (15:12 - 15:32)
# editcap -A "2017-07-05 15:12:00" -B "2017-07-05 15:32:00" cic-ids2017/Wednesday.pcap cic-ids/Heartbleed-Port444.pcapng
# editcap -A "2017-07-06 02:12:00" -B "2017-07-06 02:32:00" cic-ids2017/Wednesday.pcap cic-ids/Heartbleed-Port444.pcapng
editcap -A "2017-07-06 02:12:00" -B "2017-07-06 02:18:00" cic-ids2017/Wednesday.pcap cic-ids/Heartbleed-Port444.pcapng

# Web attack - Brute Force (2017-07-06 9:20-10 a.m.)
# editcap -A "2017-07-06 09:20:00" -B "2017-07-06 10:00:00" cic-ids2017/Thursday.pcap cic-ids/Web-BruteForce.pcapng
# editcap -A "2017-07-06 20:20:00" -B "2017-07-06 21:00:00" cic-ids2017/Thursday.pcap cic-ids/Web-BruteForce.pcapng
editcap -A "2017-07-06 20:20:00" -B "2017-07-06 20:25:00" cic-ids2017/Thursday.pcap cic-ids/Web-BruteForce.pcapng

# Web attack - XSS (2017-07-06 10:15-10:35 a.m.)
# editcap -A "2017-07-06 10:15:00" -B "2017-07-06 10:35:00" cic-ids2017/Thursday.pcap cic-ids/Web-XSS.pcapng
# editcap -A "2017-07-06 21:15:00" -B "2017-07-06 21:35:00" cic-ids2017/Thursday.pcap cic-ids/Web-XSS.pcapng
editcap -A "2017-07-06 21:15:00" -B "2017-07-06 21:25:00" cic-ids2017/Thursday.pcap cic-ids/Web-XSS.pcapng

# Web attack - Sql Injection (2017-07-06 10:40-10:42 a.m.)
# editcap -A "2017-07-06 10:40:00" -B "2017-07-06 10:42:00" cic-ids2017/Thursday.pcap cic-ids/Web-SqlInjection.pcapng
editcap -A "2017-07-06 21:40:00" -B "2017-07-06 21:42:00" cic-ids2017/Thursday.pcap cic-ids/Web-SqlInjection.pcapng

# Infiltration – Dropbox download (2017-07-06 14:19-14:21 p.m. and 14:33 -14:35 and 15:04 – 15:45 p.m.)
# editcap -A "2017-07-06 14:19:00" -B "2017-07-06 14:21:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-Dropbox-1.pcapng
# editcap -A "2017-07-07 01:19:00" -B "2017-07-07 01:21:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-Dropbox-1.pcapng
# editcap -A "2017-07-06 14:33:00" -B "2017-07-06 14:35:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-Dropbox-2.pcapng
editcap -A "2017-07-07 01:33:00" -B "2017-07-07 01:35:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-Dropbox.pcapng
# editcap -A "2017-07-06 15:04:00" -B "2017-07-06 15:45:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-Dropbox-3.pcapng
# editcap -A "2017-07-07 02:04:00" -B "2017-07-07 02:45:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-Dropbox-3.pcapng
# editcap -A "2017-07-07 02:04:00" -B "2017-07-07 02:15:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-Dropbox-3.pcapng

# Infiltration – Cool disk (2017-07-06 15:04 – 15:45 p.m.)
# editcap -A "2017-07-06 15:04:00" -B "2017-07-06 15:45:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-CoolDisk.pcapng
# editcap -A "2017-07-07 02:04:00" -B "2017-07-07 02:45:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-CoolDisk.pcapng
editcap -A "2017-07-07 02:04:00" -B "2017-07-07 02:15:00" cic-ids2017/Thursday.pcap cic-ids/Infiltration-CoolDisk.pcapng

# Botnet ARES (10:02 a.m. – 11:02 a.m.)
# editcap -A "2017-07-07 10:02:00" -B "2017-07-07 11:02:00" cic-ids2017/Friday.pcap cic-ids/Botnet-ARES.pcapng
# editcap -A "2017-07-07 21:02:00" -B "2017-07-07 22:02:00" cic-ids2017/Friday.pcap cic-ids/Botnet-ARES.pcapng
editcap -A "2017-07-07 21:02:00" -B "2017-07-07 21:10:00" cic-ids2017/Friday.pcap cic-ids/Botnet-ARES.pcapng

# Port Scan (14:01 – 14:04)
# editcap -A "2017-07-07 14:01:00" -B "2017-07-07 14:04:00" cic-ids2017/Friday.pcap cic-ids/PortScan.pcapng
editcap -A "2017-07-08 01:01:00" -B "2017-07-08 01:10:00" cic-ids2017/Friday.pcap cic-ids/PortScan.pcapng


# DDoS LOIT (15:56 – 16:16)
# editcap -A "2017-07-07 15:56:00" -B "2017-07-07 16:16:00" cic-ids2017/Friday.pcap cic-ids/DDoS-LOIT.pcapng
# editcap -A "2017-07-08 02:56:00" -B "2017-07-08 03:16:00" cic-ids2017/Friday.pcap cic-ids/DDoS-LOIT.pcapng
# editcap -A "2017-07-08 02:56:00" -B "2017-07-08 03:00:00" cic-ids2017/Friday.pcap cic-ids/DDoS-LOIT.pcapng


# cut a benign traffic
mkdir -p cic-ids-benign
editcap -A "2017-07-07 20:00:00" -B "2017-07-07 20:05:00" cic-ids2017/Friday.pcap cic-ids-benign/benign.pcapng