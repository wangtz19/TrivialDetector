# mkdir -p train_set
# editcap -c 200000 dataset/cut20200610.pcapng train_set/output.pcapng

editcap -r dataset/2020.pcapng dataset/benign_small.pcapng 1-100000