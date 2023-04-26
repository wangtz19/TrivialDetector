import pandas as pd
from utils import Packet, Flow

def get_flows(df: pd.DataFrame, key_type: str = "default") -> dict:
    mp = dict()
    for idx in range(len(df)): # simulate the process of packet processing
        row = df.iloc[idx]
        pkt = Packet(
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            proto_code=row["proto_code"],
            pkt_length=row["pkt_length"],
            timestamp=row["timestamp"],
            ttl=row["ttl"],
            tcp_window=row["tcp_window"],
            tcp_dataoffset=row["tcp_dataoffset"],
            udp_length=row["udp_length"],
            label=row["label"],
        )
        key = pkt.key(type=key_type)
        if key not in mp:
            mp[key] = Flow()
        mp[key].add_packet(pkt)
    return mp


from config import whisper_config
MAX_LEN = whisper_config["n_fft"] * 2
import torch

def transform(mp: dict, feature_type: str = "whisper", 
              data_type: str = "train", test_data_aug: bool = True):
    packet_data, flow_data = [], []
    packet_labels, flow_labels = [], []
    for key, flow in mp.items():
        vec = flow.vector()
        if feature_type == "whisper":
            if len(vec) <= (whisper_config["n_fft"] // 2):
                # packet level features
                # vec = flow.packet_vector(agg_type="mean") + flow.packet_vector(agg_type="std") \
                #     + flow.packet_vector(agg_type="max") + flow.packet_vector(agg_type="min")
                # packet_data.append(vec)
                # packet_labels.append(flow.label)

                # implement fft on short flows
                ten = torch.tensor(vec)
                ten_fft = torch.fft.fft(ten, n=(whisper_config["n_fft"] // 2)+1)
                ten_power = torch.pow(ten_fft.real, 2) + torch.pow(ten_fft.imag, 2)
                ten_res = (ten_power.squeeze()+1).log2()
                ten_res = torch.where(torch.isnan(ten_res), torch.zeros_like(ten_res), ten_res)
                ten_res = torch.where(torch.isinf(ten_res), torch.zeros_like(ten_res), ten_res)
                if data_type == "test" and test_data_aug:
                    # data shape for test data augmentation: (n_flow, n_sample, floor(n_fft/2)+1)
                    packet_data.append([ten_res.tolist()])
                else:
                    # data shape for no data augmentation: (n_flow, floor(n_fft/2)+1)
                    packet_data.append(ten_res.tolist())
                packet_labels.append(flow.label)
                
            else:
                # flow level featrues
                ten = torch.tensor(vec)
                # stft requirement: input_size > (n_fft // 2)
                # default return shape: (floor(n_fft/2)+1, n_frame, 2)
                ten_fft = torch.stft(ten, whisper_config["n_fft"])
                ten_power = torch.pow(ten_fft[:,:,0], 2) + torch.pow(ten_fft[:,:,1], 2)
                ten_res = ((ten_power.squeeze()+1).log2()).permute(1,0)
                ten_res = torch.where(torch.isnan(ten_res), torch.zeros_like(ten_res), ten_res)
                ten_res = torch.where(torch.isinf(ten_res), torch.zeros_like(ten_res), ten_res)
                # ten_res shape: (n_frame, floor(n_fft/2)+1)
                if data_type == "train":
                    if (ten_res.size(0) > whisper_config["mean_win_train"]):
                        for _ in range(whisper_config["num_train_sample"]):
                            start_idx = torch.randint(0, ten_res.size(0)
                                        - whisper_config["mean_win_train"], (1,)).item()
                            ten_tmp = ten_res[start_idx:start_idx+whisper_config["mean_win_train"],:].mean(dim=0)
                            flow_data.append(ten_tmp.tolist())
                            flow_labels.append(flow.label)
                    else:
                        flow_data.append(ten_res.mean(dim=0).tolist())
                        flow_labels.append(flow.label)
                else: # for test
                    if test_data_aug:
                        tmp_data = []
                        if (ten_res.size(0) > whisper_config["mean_win_test"]):
                            # data augmentation for kmeans on flows with length > mean_win_test
                            for idx in range(0, ten_res.size(0) - whisper_config["mean_win_test"], 
                                            whisper_config["mean_win_test"]):
                                ten_tmp = ten_res[idx:idx+whisper_config["mean_win_test"],:].mean(dim=0)
                                tmp_data.append(ten_tmp.tolist())
                        else:
                            # no data augmentation for kmeans on flows with length < mean_win_test
                            tmp_data.append(ten_res.mean(dim=0).tolist())
                        flow_data.append(tmp_data)
                        # data shape for augmentation: (n_flow, n_sample, floor(n_fft/2)+1)
                    else: # for other detection methods
                        flow_data.append(ten_res.mean(dim=0).tolist())
                        # data shape for no augmentation: (n_flow, floor(n_fft/2)+1)
                    flow_labels.append(flow.label)
        elif feature_type == "encoding":
            # directly use the whisper encoding vector
            if len(vec) >= MAX_LEN:
                new_vec = vec[:MAX_LEN]
            else:
                new_vec = vec + [0] * (MAX_LEN - len(vec))
            if len(vec) <= (whisper_config["n_fft"] // 2):
                packet_data.append(new_vec)
                packet_labels.append(flow.label)
            else:
                flow_data.append(new_vec)
                flow_labels.append(flow.label)
        else: # for other feature types
            pass
    return packet_data, packet_labels, flow_data, flow_labels



import torch.nn as nn

class AutoEncoder(nn.Module):
    def __init__(self, input_dim, hidden_dim=None, decoder_sigmoid=False):
        super(AutoEncoder, self).__init__()
        if hidden_dim is None:
            hidden_dim = int(0.75 * input_dim)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.Sigmoid())
        if decoder_sigmoid:
            self.decoder = nn.Sequential(
                nn.Linear(hidden_dim, input_dim),
                nn.Sigmoid())
        else:
            self.decoder = nn.Linear(hidden_dim, input_dim)
    
    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)
        return x
    

class Dataset(torch.utils.data.Dataset):
    def __init__(self, data, labels):
        super(Dataset, self).__init__()
        self.data = data
        self.labels = labels
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        return self.data[idx], self.labels[idx]
    

from sklearn.cluster import KMeans
import os
import json

def train(train_data, save_path, n_clusters):
    train_data = torch.tensor(train_data)
    kmeans = KMeans(n_clusters=n_clusters, random_state=0)
    kmeans.fit(train_data.cpu().numpy())

    centroids = torch.tensor(kmeans.cluster_centers_)
    train_loss = torch.cdist(train_data, centroids, p=2).min(dim=1).values.mean()

    if not os.path.exists(os.path.dirname(save_path)):
        os.makedirs(os.path.dirname(save_path))
    with open(save_path, "w") as f:
        json.dump({
            "centroids": centroids.tolist(),
            "train_loss": train_loss.item(),
        }, f)


import os
import json

def test(test_data, load_path, save_path):
    with open(load_path, "r") as f:
        centroids = json.load(f)["centroids"]
    centroids = torch.tensor(centroids)
    
    test_res = []
    for key, val in test_data.items():
        val = torch.tensor(val)
        if (val.size(0) > whisper_config["mean_win_test"]):
            max_dist = 0
            for idx in range(0, val.size(0) - whisper_config["mean_win_test"], 
                             whisper_config["mean_win_test"]):
                ten_tmp = val[idx:idx+whisper_config["mean_win_test"],:].mean(dim=0)
                dist = torch.norm(ten_tmp - centroids, dim=1).min()
                max_dist = max(max_dist, dist)
            min_dist = max_dist
        else:
            min_dist = torch.norm(val.mean(dim=0) - centroids, dim=1).min()
        test_res.append({"key": key, "loss": min_dist.item()})

    if not os.path.exists(os.path.dirname(save_path)):
        os.makedirs(os.path.dirname(save_path))
    with open(save_path, "w") as f:
        json.dump(test_res, f)

