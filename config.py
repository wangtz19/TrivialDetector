# Whisper config

whisper_config = {
    "n_fft": 50,
    "mean_win_train": 50,
    "mean_win_test": 100,
    "num_train_sample": 50,
    "save_to_file": True,
    "save_dir": "whisper",
    "save_file_prefix": "",

    # kmeans
    "num_train_data": 500, # default 2000
    "val_K": 10,
}