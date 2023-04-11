import pandas as pd
from utils import Packet, Flow

def get_flows(df: pd.DataFrame, key_type: str = "default") -> dict:
    mp = dict()
    for idx in range(len(df)): # simulate the process of packet processing
        row = df.iloc[idx]
        pkt = Packet(
            src_addr=row["src_addr"],
            dst_addr=row["dst_addr"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            proto_code=row["proto_code"],
            pkt_length=row["pkt_length"],
            timestamp=row["timestamp"],
        )
        key = pkt.key(type=key_type)
        if key not in mp:
            mp[key] = Flow()
        mp[key].add_packet(pkt)
    return mp


import torch
from config import whisper_config

def transform(mp: dict, feature_type: str = "whisper", data_type: str = "train"):
    train_data = []
    test_data = {}
    for key, flow in mp.items():
        vec = flow.vector(type=feature_type)
        if feature_type == "whisper":
            if len(vec) <= (whisper_config["n_fft"] // 2):
                print(f"short flow: {key}, flow length: {len(vec)}, skip...")
                continue
                # todo: change to packet level feature

            ten = torch.tensor(vec)
            # stft requirement: input_size > (n_fft // 2)
            # default return shape: (floor(n_fft/2)+1, n_frame, 2)
            ten_fft = torch.stft(ten, whisper_config["n_fft"])
            ten_power = torch.pow(ten_fft[:,:,0], 2) + torch.pow(ten_fft[:,:,1], 2)
            ten_res = ((ten_power.squeeze()+1).log2()).permute(1,0)
            ten_res = torch.where(torch.isnan(ten_res), torch.zeros_like(ten_res), ten_res)
            ten_res = torch.where(torch.isinf(ten_res), torch.zeros_like(ten_res), ten_res)
            if data_type == "train":
                if (ten_res.size(0) > whisper_config["mean_win_train"]):
                    for _ in range(whisper_config["num_train_sample"]):
                        start_idx = torch.randint(0, ten_res.size(0)
                                    - whisper_config["mean_win_train"], (1,)).item()
                        ten_tmp = ten_res[start_idx:start_idx+whisper_config["mean_win_train"],:].mean(dim=0)
                        train_data.append(ten_tmp.tolist())
                else:
                    train_data.append(ten_res.mean(dim=0).tolist())
            else: # for test
                tmp_data = []
                if (ten_res.size(0) > whisper_config["mean_win_test"]):
                    for idx in range(0, ten_res.size(0) - whisper_config["mean_win_test"], 
                                     whisper_config["mean_win_test"]):
                        ten_tmp = ten_res[idx:idx+whisper_config["mean_win_test"],:].mean(dim=0)
                        tmp_data.append(ten_tmp.tolist())
                else:
                    tmp_data.append(ten_res.mean(dim=0).tolist())
                test_data[key] = tmp_data
        else: # for other feature types
            pass
    if data_type == "train":
        return train_data
    else:
        return test_data
    

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

