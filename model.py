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
import torch

MAX_LEN = whisper_config["n_fft"] * 2

def fft_module(vec):
    ten = torch.tensor(vec)
    ten_fft = torch.fft.fft(ten, n=(whisper_config["n_fft"] // 2)+1)
    ten_power = torch.pow(ten_fft.real, 2) + torch.pow(ten_fft.imag, 2)
    ten_res = (ten_power.squeeze()+1).log2()
    ten_res = torch.where(torch.isnan(ten_res), torch.zeros_like(ten_res), ten_res)
    ten_res = torch.where(torch.isinf(ten_res), torch.zeros_like(ten_res), ten_res)
    return ten_res

def stft_module(vec):
    ten = torch.tensor(vec)
    # stft requirement: input_size > (n_fft // 2)
    # default return shape: (floor(n_fft/2)+1, n_frame, 2)
    ten_fft = torch.stft(ten, whisper_config["n_fft"])
    ten_power = torch.pow(ten_fft[:,:,0], 2) + torch.pow(ten_fft[:,:,1], 2)
    ten_res = ((ten_power.squeeze()+1).log2()).permute(1,0)
    ten_res = torch.where(torch.isnan(ten_res), torch.zeros_like(ten_res), ten_res)
    ten_res = torch.where(torch.isinf(ten_res), torch.zeros_like(ten_res), ten_res)
    # ten_res shape: (n_frame, floor(n_fft/2)+1)
    return ten_res

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
                ten_res = fft_module(vec)
                if data_type == "test" and test_data_aug:
                    # data shape for test data augmentation: (n_flow, n_sample, floor(n_fft/2)+1)
                    packet_data.append([ten_res.tolist()])
                else:
                    # data shape for no data augmentation: (n_flow, floor(n_fft/2)+1)
                    packet_data.append(ten_res.tolist())
                packet_labels.append(flow.label)
                
            else:
                # flow level featrues
                ten_res = stft_module(vec)
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


def train_kmeans(train_data, kmeans_save_path, n_clusters=10):
    train_data = torch.tensor(train_data).float()
    kmeans = KMeans(n_clusters=n_clusters, random_state=0)
    kmeans.fit(train_data)
    centroids = torch.tensor(kmeans.cluster_centers_).float()
    train_loss = torch.cdist(train_data, centroids, p=2).min(dim=1).values
    if not os.path.exists(os.path.dirname(kmeans_save_path)):
        os.makedirs(os.path.dirname(kmeans_save_path))
    with open(kmeans_save_path, "w") as f:
        json.dump({
            "centroids": centroids.tolist(),
            "train_loss": train_loss.mean().item(),
            "train_loss_list": train_loss.cpu().tolist()
        }, f, indent=4)


def train_ae(train_data, train_labels, save_dir,
            model, criterion, optimizer, device, 
            batch_size=32, num_epochs=200, 
            decoder_sigmoid=False):
    train_dataset = Dataset(train_data, train_labels)
    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    loss_list = []
    model.to(device)
    model.train()
    for epoch in range(num_epochs):
        for data, labels in train_loader:
            if decoder_sigmoid:
                data = torch.sigmoid(data.to(device).float())
            else:
                data = data.to(device).float()
            optimizer.zero_grad()
            outputs = model(data)
            loss = criterion(outputs, data)
            loss_list.append(loss.item())
            loss.backward()
            optimizer.step()
        print(f"Epoch {epoch+1}/{num_epochs}, Loss: {loss.item():.4f}")
    os.makedirs(save_dir, exist_ok=True)
    model_save_path = os.path.join(save_dir, "model.pt")
    torch.save(model.state_dict(), model_save_path)
    loss_save_path = os.path.join(save_dir, "train_loss.json")
    with open(loss_save_path, "w") as f:
        json.dump(loss_list, f)


def test_kmeans(data, kmeans_load_path, whisper_config, scale=10):
    with open(kmeans_load_path, "r") as f:
        model_param = json.load(f)
    centroids = torch.tensor(model_param["centroids"])
    train_loss = model_param["train_loss"]

    kmeans_preds, kmeans_ratios, test_loss_list = [], [], []
    for val in data:
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
        test_loss_list.append(min_dist)
        kmeans_preds.append(-1 if min_dist > scale * train_loss else 1)
        kmeans_ratios.append(min_dist/(scale * train_loss))
    
    return kmeans_preds, kmeans_ratios, test_loss_list, scale*train_loss


def test_ae(test_data, model, device, criterion, 
            threshold, scale=5, test_data_aug=False,
            decoder_sigmoid=False):
    model.eval()
    preds, ratios, loss_list = [], [], []
    with torch.no_grad():
        for val in test_data:
            if decoder_sigmoid:
                data = torch.sigmoid(torch.tensor(val).to(device)).float()
            else:
                data = torch.tensor(val).to(device).float()
            outputs = model(data)
            loss = criterion(outputs, data)
            if not test_data_aug:
                ratios.append(loss.item()/(scale * threshold))
                preds.append(-1 if loss.item() > threshold * scale else 1)
                loss_list.append(loss.item())
            else:
                ratios.append(loss.max().item()/(scale * threshold))
                preds.append(-1 if loss.max().item() > threshold * scale else 1)
                loss_list.append(loss.max().item())

    return preds, ratios, loss_list, scale*threshold


from sklearn.metrics import accuracy_score, roc_curve, auc, precision_score, recall_score, f1_score
import numpy as np
def get_metrics(y_true, y_pred, pos_label=-1, neg_label=1):
    acc = accuracy_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred, pos_label=pos_label)
    precision = precision_score(y_true, y_pred, pos_label=pos_label)
    f1 = f1_score(y_true, y_pred, pos_label=pos_label)
    try:
        tpr = np.sum(np.array(y_true) == pos_label & np.array(y_pred) == pos_label) \
            / np.sum(np.array(y_true) == pos_label)
    except:
        tpr = np.nan
    try:
        fpr = np.sum(np.array(y_true) == neg_label & np.array(y_pred) == pos_label) \
            / np.sum(np.array(y_true) == neg_label)
    except:
        fpr = np.nan
    try:
        _fpr, _tpr, _ = roc_curve(y_true, y_pred, pos_label=pos_label)
        auc_score = auc(_fpr, _tpr)
        eer = _fpr[np.nanargmin(np.absolute((_fpr + _tpr) - 1))]
    except:
        auc_score = np.nan
        eer = np.nan
    return acc, recall, precision, f1, tpr, fpr, auc_score, eer


def test_ensemble(datac, dataw, labels, kmeans_load_path,
         aec_input_dim, aec_load_path, aew_input_dim, aew_load_path, 
         kmeans_scale=7, aec_scale=10, aew_scale=3,
         test_data_aug=False, vote_method="majority", plot_dir=None):
    
    kmeans_preds, kmeans_ratios, kmeans_loss_list, kmeans_threshold = \
        test_kmeans(dataw, kmeans_load_path, whisper_config, scale=kmeans_scale)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    criterion = nn.MSELoss()

    model_aec = AutoEncoder(aec_input_dim, decoder_sigmoid=True)
    model_aec.load_state_dict(torch.load(os.path.join(aec_load_path, "model.pt")))
    model_aec.to(device)
    with open(os.path.join(aec_load_path, "train_loss.json"), "r") as f:
        loss_list = json.load(f)
    threshold = torch.tensor(loss_list).mean().item()
    aec_preds, aec_ratios, aec_loss_list, aec_threshold = \
        test_ae(datac, model_aec, device, criterion, threshold, 
                scale=aec_scale, test_data_aug=False, decoder_sigmoid=True) 
    
    model_aew = AutoEncoder(aew_input_dim)
    model_aew.load_state_dict(torch.load(os.path.join(aew_load_path, "model.pt")))
    model_aew.to(device)
    with open(os.path.join(aew_load_path, "train_loss.json"), "r") as f:
        loss_list = json.load(f)
    threshold = torch.tensor(loss_list).mean().item()
    aew_preds, aew_ratios, aew_loss_list, aew_threshold = \
        test_ae(dataw, model_aew, device, criterion, threshold, 
                scale=aew_scale, test_data_aug=test_data_aug, decoder_sigmoid=False)

    # preds = np.sign(np.array(kmeans_preds) + np.array(aec_preds) + np.array(aew_preds))
    preds_majority, preds_positive, preds_weighted = [], [], []
    for idx in range(len(kmeans_preds)):
        preds_majority.append(np.sign(kmeans_preds[idx] + aec_preds[idx] + aew_preds[idx]))
        if kmeans_preds[idx] == -1 or aec_preds[idx] == -1 or aew_preds[idx] == -1:
            preds_positive.append(-1)
        else:
            preds_positive.append(1)
        preds_weighted.append(np.sign(kmeans_preds[idx] * kmeans_ratios[idx] +
                                        aec_preds[idx] * aec_ratios[idx] + 
                                        aew_preds[idx] * aew_ratios[idx]))
    return {
        "labels": labels,
        "kmeans": kmeans_preds,
        "aec": aec_preds,
        "aew": aew_preds,
        "preds_majority": preds_majority,
        "preds_positive": preds_positive,
        "preds_weighted": preds_weighted,
    }


def get_ensemble_result(df_test, test_data_aug, use_short_flow, 
                        kmeans_load_path, aec_input_dim, aec_load_path, 
                        aew_input_dim, aew_load_path, vote_method="majority",
                        plot_dir=None, kmeans_scale=7, aec_scale=10, aew_scale=3):
    
    test_packet_data, test_packet_labels, test_flow_data, test_flow_labels  \
    = transform(get_flows(df_test), feature_type="encoding" 
                ,data_type="test", test_data_aug=test_data_aug)
    data_encoding = test_flow_data if not use_short_flow else test_flow_data + test_packet_data
    labels_encoding = test_flow_labels if not use_short_flow else test_flow_labels + test_packet_labels

    test_packet_data, test_packet_labels, test_flow_data, test_flow_labels \
    = transform(get_flows(df_test), data_type="test", test_data_aug=test_data_aug)
    data_whisper = test_flow_data if not use_short_flow else test_flow_data + test_packet_data
    labels_whisper = test_flow_labels if not use_short_flow else test_flow_labels + test_packet_labels

    assert len(labels_encoding) == len(labels_whisper), \
        print(f"len labels_encoding: {len(labels_encoding)}, len labels_whisper: {len(labels_whisper)}")
    for idx in range(len(labels_encoding)):
        assert labels_encoding[idx] == labels_whisper[idx]
    
    data_dict = test_ensemble(data_encoding, data_whisper, labels_whisper, 
                        kmeans_load_path, aec_input_dim, aec_load_path, aew_input_dim, 
                        aew_load_path, test_data_aug=test_data_aug, vote_method=vote_method,
                        kmeans_scale=kmeans_scale, aec_scale=aec_scale, aew_scale=aew_scale)
    
    # if plot_dir is not None:
    #     plot_cdf(, kmeans_loss_list, "kmeans", plot_dir)

    metric_dict = {}
    for key in ["kmeans", "aec", "aew", "preds_majority", "preds_positive", "preds_weighted"]:
        metric_dict[key] = get_metrics(data_dict["labels"], data_dict[key])
    
    return metric_dict

