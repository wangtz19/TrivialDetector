from matplotlib import pyplot as plt
from collections import Counter, OrderedDict
import numpy as np


# color-blindness friendly
CB_color_cycle = ['#377eb8', '#ff7f00', '#4daf4a',
                  '#f781bf', '#a65628', '#984ea3',
                  '#999999', '#e41a1c', '#dede00']

def vals2cdf(vals):
    dist_dict = dict(Counter(vals))
    dist_dict = {k: v for k, v in sorted(dist_dict.items(), key = lambda x: x[0])}
    x = dist_dict.keys()

    pdf = np.asarray(list(dist_dict.values()), dtype=float) / float(sum(dist_dict.values()))
    cdf = np.cumsum(pdf)

    return x, cdf


# syn_df_dict: {name: dict}
def plot_cdf(benign_arr, attack_arr, xlabel, ylabel, plot_loc, 
             title=None, x_logscale=False, y_logscale=False,
             benign_legend="benign", attack_legend="attack"):
    plt.clf()

    x, cdf = vals2cdf(benign_arr)
    plt.plot(x, cdf, label=benign_legend, color=CB_color_cycle[4], linewidth=3)

    x, cdf = vals2cdf(attack_arr)
    plt.plot(x, cdf, label=attack_legend, color=CB_color_cycle[0], linewidth=3)

    plt.xlabel(xlabel, fontsize=14)
    plt.ylabel(ylabel, fontsize=14)
    plt.legend(fontsize=18)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    if title is not None:
        plt.title(title, fontsize=20)

    if x_logscale:
        plt.xscale('log')
    if y_logscale:
        plt.yscale('log')

    plt.savefig(plot_loc, bbox_inches="tight", dpi=300)
    plt.show()


def plot_line(benign_arr, attack_arr, xlabel, ylabel, plot_loc, 
             title=None, x_logscale=False, y_logscale=False,
             benign_legend="benign", attack_legend="attack"):
    plt.clf()

    plt.plot(np.arange(benign_arr), benign_arr, label=benign_legend, color=CB_color_cycle[4], linewidth=3)
    plt.plot(np.arange(attack_arr), attack_arr, label=attack_legend, color=CB_color_cycle[4], linewidth=3)

    plt.xlabel(xlabel, fontsize=14)
    plt.ylabel(ylabel, fontsize=14)
    plt.legend(fontsize=18)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    if title is not None:
        plt.title(title, fontsize=20)

    if x_logscale:
        plt.xscale('log')
    if y_logscale:
        plt.yscale('log')

    plt.savefig(plot_loc, bbox_inches="tight", dpi=300)
    plt.show()
