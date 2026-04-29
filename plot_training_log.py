import re
import matplotlib.pyplot as plt

def parse_log(log_path):
    epochs = []
    pos_ratios = []          # positive_reward / total
    reward_means = []
    compile_rates = []       # compile_ok / total
    smartbugs_improves = []

    with open(log_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        # 查找 "reward stats. epoch: X"
        if 'reward stats. epoch:' in line:
            # 提取 epoch 数字
            epoch_match = re.search(r'epoch:\s*(\d+)', line)
            if not epoch_match:
                i += 1
                continue
            epoch = int(epoch_match.group(1))

            # 提取 mean reward
            mean_match = re.search(r'mean:\s*([-\d.]+)', line)
            mean_reward = float(mean_match.group(1)) if mean_match else None

            # 下一行有 "reward breakdown" 包含 positive, zero_or_negative, smartbugs_improve
            if i+1 < len(lines) and 'reward breakdown' in lines[i+1]:
                breakdown_line = lines[i+1]
                pos_match = re.search(r'positive:\s*(\d+)', breakdown_line)
                neg_match = re.search(r'zero_or_negative:\s*(\d+)', breakdown_line)
                improve_match = re.search(r'smartbugs_improve:\s*(\d+)', breakdown_line)
                if pos_match and neg_match:
                    pos = int(pos_match.group(1))
                    neg = int(neg_match.group(1))
                    total = pos + neg
                    pos_ratio = pos / total if total > 0 else 0
                else:
                    pos_ratio = None
                smartbugs_improve = int(improve_match.group(1)) if improve_match else None
            else:
                pos_ratio = None
                smartbugs_improve = None

            # 再下一行有 "compile pass rate"
            compile_line = lines[i+2] if i+2 < len(lines) else ""
            compile_match = re.search(r'compile pass rate.*?(\d+)/(\d+)', compile_line)
            if compile_match:
                compile_ok = int(compile_match.group(1))
                compile_total = int(compile_match.group(2))
                compile_rate = compile_ok / compile_total if compile_total > 0 else 0
            else:
                compile_rate = None

            # 保存数据
            epochs.append(epoch)
            pos_ratios.append(pos_ratio)
            reward_means.append(mean_reward)
            compile_rates.append(compile_rate)
            smartbugs_improves.append(smartbugs_improve)

            i += 3  # 跳过已处理的行
        else:
            i += 1

    return epochs, pos_ratios, reward_means, compile_rates, smartbugs_improves


def plot_metrics(epochs, pos_ratios, reward_means, compile_rates, smartbugs_improves):
    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle('RL Training Metrics Over Epochs', fontsize=16)

    # 图1: positive reward / total
    ax1 = axes[0, 0]
    ax1.plot(epochs, pos_ratios, marker='o', linestyle='-', color='green')
    ax1.set_xlabel('Epoch')
    ax1.set_ylabel('Positive Reward / Total')
    ax1.set_title('Positive Reward Ratio')
    ax1.grid(True, linestyle='--', alpha=0.7)

    # 图2: reward mean
    ax2 = axes[0, 1]
    ax2.plot(epochs, reward_means, marker='s', linestyle='-', color='blue')
    ax2.set_xlabel('Epoch')
    ax2.set_ylabel('Mean Reward')
    ax2.set_title('Mean Reward')
    ax2.grid(True, linestyle='--', alpha=0.7)

    # 图3: compile pass rate
    ax3 = axes[1, 0]
    ax3.plot(epochs, compile_rates, marker='^', linestyle='-', color='red')
    ax3.set_xlabel('Epoch')
    ax3.set_ylabel('Compile Pass Rate')
    ax3.set_title('Compile Success Ratio')
    ax3.grid(True, linestyle='--', alpha=0.7)

    # 图4: smartbugs_improve
    ax4 = axes[1, 1]
    ax4.plot(epochs, smartbugs_improves, marker='d', linestyle='-', color='purple')
    ax4.set_xlabel('Epoch')
    ax4.set_ylabel('SmartBugs Improve Count')
    ax4.set_title('SmartBugs Improvement per Epoch')
    ax4.grid(True, linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig('training_curves.png', dpi=150)
    plt.show()


if __name__ == '__main__':
    log_file = 'train_log_6.txt'  # 请确保日志文件名与此一致
    epochs, pos_ratios, reward_means, compile_rates, smartbugs_improves = parse_log(log_file)

    # 过滤掉 RL 之前的数据（epoch 0-19 是监督训练，没有 reward 统计）
    start_idx = next((i for i, e in enumerate(epochs) if e >= 20), 0)
    epochs = epochs[start_idx:]
    pos_ratios = pos_ratios[start_idx:]
    reward_means = reward_means[start_idx:]
    compile_rates = compile_rates[start_idx:]
    smartbugs_improves = smartbugs_improves[start_idx:]

    plot_metrics(epochs, pos_ratios, reward_means, compile_rates, smartbugs_improves)
    print("图表已保存为 training_curves6.png")