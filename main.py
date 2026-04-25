from utils2 import *
from genetic import *
import os
import pickle
import re
import sys

class Config_RL_multistep:
    def __init__(self):
        self.EMB_SIZE = 512
        self.ENC_SIZE = 512
        self.DEC_SIZE = 512
        self.MODEL_SIZE = 512
        self.ATTN_SIZE = 512
        self.NUM_LAYER = 2
        self.SEED = 1234
        self.DICT_SIZE_1 = 860
        self.ACTION_NUM = len(get_action())
        self.DICT_SIZE_2 = 350
        self.PRE_BATCH_SIZE = 16
        self.BATCH_SIZE = 64
        self.MAX_INPUT_SIZE = 400
        self.MAX_OUTPUT_SIZE = 5
        self.PRE_EPOCH = 20
        self.EPOCH = 100
        self.DROPOUT = 0.25
        self.LR = 1e-5
        self.START_TOKEN = 0
        self.END_TOKEN = 101


def summarize_rewards(epoch, reward_details, logger):
    if not reward_details:
        return 0.0, 0

    rewards = [detail['reward'] for detail in reward_details]
    total = len(reward_details)
    mean_reward = sum(rewards) / total
    min_reward = min(rewards)
    max_reward = max(rewards)
    non_negative = sum(1 for reward in rewards if reward >= 0)
    negative = total - non_negative

    compile_ok = sum(detail.get('compile_ok', 0) for detail in reward_details)
    compile_fail = sum(detail.get('compile_fail', 0) for detail in reward_details)
    invalid_action = sum(detail.get('invalid_action', 0) for detail in reward_details)
    smartbugs_used = sum(detail.get('smartbugs_used', 0) for detail in reward_details)
    smartbugs_improve = sum(detail.get('smartbugs_improve', 0) for detail in reward_details)
    smartbugs_equal = sum(detail.get('smartbugs_equal', 0) for detail in reward_details)
    smartbugs_worse = sum(detail.get('smartbugs_worse', 0) for detail in reward_details)
    similarity_used = sum(detail.get('similarity_used', 0) for detail in reward_details)
    entropy_used = sum(detail.get('entropy_used', 0) for detail in reward_details)
    compile_reward = sum(detail.get('compile_reward', 0.0) for detail in reward_details)
    detect_reward = sum(detail.get('detect_reward', 0.0) for detail in reward_details)
    similarity_reward = sum(detail.get('similarity_reward', 0.0) for detail in reward_details)
    entropy_reward = sum(detail.get('entropy_reward', 0.0) for detail in reward_details)
    action_reward = sum(detail.get('action_reward', 0.0) for detail in reward_details)
    positive = sum(1 for reward in rewards if reward > 0)
    zero_or_negative = total - positive

    samples = []
    for detail in reward_details[:6]:
        samples.append('{}:{}:{:.6f}'.format(detail.get('status', 'unknown'), detail['contract'], detail['reward']))
    sample_text = ' | '.join(samples) if samples else 'none'

    logger.info(
        'reward stats. epoch: {}. mean: {:.6f}, min: {:.6f}, max: {:.6f}, non_negative: {}, negative: {}'.format(
            epoch, mean_reward, min_reward, max_reward, non_negative, negative
        )
    )
    logger.info(
        'reward breakdown. epoch: {}. compile_ok: {}, compile_fail: {}, invalid_action: {}, smartbugs_used: {}, smartbugs_improve: {}, smartbugs_equal: {}, smartbugs_worse: {}, similarity_used: {}, entropy_used: {}, positive: {}, zero_or_negative: {}'.format(
            epoch, compile_ok, compile_fail, invalid_action, smartbugs_used, smartbugs_improve, smartbugs_equal, smartbugs_worse, similarity_used, entropy_used, positive, zero_or_negative
        )
    )
    logger.info(
        'compile pass rate. epoch: {}. {}/{} = {:.4f}'.format(
            epoch, compile_ok, total, compile_ok / total if total else 0.0
        )
    )
    logger.info(
        'reward components. epoch: {}. compile: {:.6f}, detect: {:.6f}, similarity: {:.6f}, entropy: {:.6f}, action: {:.6f}'.format(
            epoch, compile_reward, detect_reward, similarity_reward, entropy_reward, action_reward
        )
    )
    logger.info('reward samples. epoch: {}. {}'.format(epoch, sample_text))
    for detail in reward_details:
        logger.info(
            'candidate reward. epoch: {}. contract: {}. total: {:.6f}, compile: {:.6f}, detect: {:.6f}, similarity: {:.6f}, entropy: {:.6f}, action: {:.6f}, status: {}'.format(
                epoch,
                detail.get('contract', 'unknown'),
                detail.get('reward', 0.0),
                detail.get('compile_reward', 0.0),
                detail.get('detect_reward', 0.0),
                detail.get('similarity_reward', 0.0),
                detail.get('entropy_reward', 0.0),
                detail.get('action_reward', 0.0),
                detail.get('status', 'unknown'),
            )
        )
    return mean_reward, non_negative

def get_periodic_checkpoint_path(model_dir, model_name, epoch):
    return os.path.join(model_dir, '{}_train_epoch_{}.pt'.format(model_name, epoch))

def find_latest_train_checkpoint(model_dir, model_name):
    latest_epoch = -1
    latest_path = None
    pattern = re.compile(r'^{}_train_epoch_(\d+)\.pt$'.format(re.escape(model_name)))
    for name in os.listdir(model_dir):
        matched = pattern.match(name)
        if matched is None:
            continue
        epoch = int(matched.group(1))
        if epoch > latest_epoch:
            latest_epoch = epoch
            latest_path = os.path.join(model_dir, name)
    return latest_path, latest_epoch


if __name__ == "__main__":
    model_name = sys.argv[1]  # "multistep_RLRep" or "mutation"
    path = sys.argv[2]  # "dataset_vul/newALLBUGS"
    
    logger = get_logger('dataset_vul/newALLBUGS/log/{}_logging.txt'.format(model_name))
    with open('{}/code_w2i.pkl'.format(path), 'rb') as f, open('{}/ast_w2i.pkl'.format(path), 'rb') as f2:
        code_w2i = pickle.load(f)
        ast_w2i = pickle.load(f2)
    with open('{}/code_i2w.pkl'.format(path), 'rb') as f3, open('{}/ast_i2w.pkl'.format(path), 'rb') as f4:
        code_i2w = pickle.load(f3)
        ast_i2w = pickle.load(f4)
    action = []
    best_positive_repair = 10
    config = Config_RL_multistep()

    start = -1
    checkpoint_every = 5
    if model_name == 'multistep_RLRep':
        from multistep_RLRep import *
        in_w2i = (code_w2i, ast_w2i)
        model = Model(config)
        beam_search_use = 5
        model_dir = 'dataset_vul/newALLBUGS/model'
        os.makedirs(model_dir, exist_ok=True)
        resume_path, resume_epoch = find_latest_train_checkpoint(model_dir, model_name)
        if resume_path is not None:
            checkpoint = model.load(resume_path)
            start = checkpoint.get('epoch', resume_epoch)
            best_positive_repair = checkpoint.get('best_positive_repair', best_positive_repair)
            logger.info('Resume checkpoint: {} (epoch={})'.format(resume_path, start))
        elif start != -1:
            model.load('dataset_vul/newALLBUGS/model/multistep_RLRep_33')
            model.set_trainer()

        for epoch in range(start+1, config.PRE_EPOCH):
            loss = 0
            code_dir = 'dataset_vul/newALLBUGS/pretrain/threelines-tokenseq'
            ast_dir = 'dataset_vul/newALLBUGS/pretrain/ast'
            for step, batch in enumerate(get_batch(code_dir, ast_dir, config, in_w2i, pretrain=True)):
                batch_in1, batch_in2, batch_in3, batch_out = batch
                loss += model.pretrain(batch[:-2], batch[-1], 'actor')
                logger.info('Epoch: {}, Batch: {}, Loss: {}'.format(epoch, step, loss / (step + 1)))
            # Old behavior saved a full checkpoint every pretrain epoch.
            # model.save('dataset_vul/newALLBUGS/model/{}_{}'.format(model_name, epoch))
            if (epoch + 1) % checkpoint_every == 0:
                model.save(get_periodic_checkpoint_path(model_dir, model_name, epoch), epoch=epoch, best_positive_repair=best_positive_repair)

        train_start_epoch = max(config.PRE_EPOCH, start + 1)
        for epoch in range(train_start_epoch, config.EPOCH):
            loss_actor = 0
            loss_critic = 0.
            code_dir = 'dataset_vul/newALLBUGS/threelines-tokenseq'
            ast_dir = 'dataset_vul/newALLBUGS/ast'
            for step, batch in enumerate(get_batch(code_dir, ast_dir, config, in_w2i, pretrain=False)):
                batch_in1, batch_in2, batch_in3 = batch
                loss = model(batch[:-1], True, batch[-1])
                loss_actor += loss
                logger.info('Epoch: {}, Batch: {}, Loss: actor:{}'.format(epoch, step, loss_actor / (step + 1),))

            preds, ats, names, rewards, reward_details = [], [], [], [], []
            valid_code_dir = "dataset_vul/newALLBUGS/validation/threelines-tokenseq"
            valid_ast_dir = "dataset_vul/newALLBUGS/validation/ast"
            for step, batch in enumerate(get_batch(valid_code_dir, valid_ast_dir, config, in_w2i, pretrain=False)):
                batch_in1, batch_in2, batch_in3 = batch
                if beam_search_use > 0:
                    pred = model(batch[:-1], False, size=beam_search_use)
                else:
                    pred = model(batch[:-1], False, size=beam_search_use)
                for at in pred:
                    ats.append(at)
                for name in batch_in3:
                    names.append(name)
            for tup in zip(ats, names):
                reward = choose_action(tup[1], tup[0], False)
                rewards.append(reward)
                detail = get_last_fitness_details()
                if reward == -0.03:
                    detail = {
                        'contract': tup[1] + '.sol',
                        'reward': reward,
                        'compile_reward': 0.0,
                        'detect_reward': 0.0,
                        'similarity_reward': 0.0,
                        'entropy_reward': 0.0,
                        'action_reward': reward,
                        'compile_ok': 0,
                        'compile_fail': 0,
                        'invalid_action': 1,
                        'smartbugs_used': 0,
                        'smartbugs_improve': 0,
                        'smartbugs_equal': 0,
                        'smartbugs_worse': 0,
                        'similarity_used': 0,
                        'entropy_used': 0,
                        'status': 'invalid_action',
                    }
                elif detail is None:
                    detail = {
                        'contract': tup[1] + '.sol',
                        'reward': reward,
                        'compile_reward': 0.0,
                        'detect_reward': 0.0,
                        'similarity_reward': 0.0,
                        'entropy_reward': 0.0,
                        'action_reward': 0.0,
                        'compile_ok': 0,
                        'compile_fail': 0,
                        'invalid_action': 0,
                        'smartbugs_used': 0,
                        'smartbugs_improve': 0,
                        'smartbugs_equal': 0,
                        'smartbugs_worse': 0,
                        'similarity_used': 0,
                        'entropy_used': 0,
                        'status': 'unknown',
                    }
                reward_details.append(detail)

            positive_repair = 0
            for x in rewards:
                if x >= 0:
                    positive_repair += 1
            mean_reward, _ = summarize_rewards(epoch, reward_details, logger)
            if positive_repair > best_positive_repair:
                best_positive_repair = positive_repair
                print('model update. the {0}-th epoch. positive reward / total : {1} / {2}, mean reward: {3:.6f}'.format(epoch, positive_repair, len(names), mean_reward))
                model.save(os.path.join(model_dir, '{}_{}'.format(model_name, epoch)), epoch=epoch, best_positive_repair=best_positive_repair)
            else:
                print('model NOT update. the {0}-th epoch. positive reward / total : {1} / {2}, mean reward: {3:.6f}'.format(epoch, positive_repair, len(names), mean_reward))
            if (epoch + 1) % checkpoint_every == 0:
                model.save(get_periodic_checkpoint_path(model_dir, model_name, epoch), epoch=epoch, best_positive_repair=best_positive_repair)

                
    if model_name == 'mutation':
        with open("dataset_vul/newALLBUGS/dicts/v_code_w2i.pkl", 'rb') as tf, open("dataset_vul/newALLBUGS/dicts/v_code_i2w.pkl", 'rb') as tf2:
            val_code_w2i, val_code_i2w = pickle.load(tf), pickle.load(tf2)
        valid_code_dir = "dataset_vul/newALLBUGS/validation/contract/"
        
        for contract_name in os.listdir(valid_code_dir):
            print("processing {}:".format(contract_name))
            valid_code_path = valid_code_dir + contract_name
            addr = contract_name.split('.sol')[0]
            mutation_path = valid_code_path
            gen = 0
            while True:
                print("processing the {}-th generation mutation...".format(gen))
                repair_dir = 'dataset_vul/newALLBUGS/validation/genetic/{}/{}/'.format(addr, gen)
                os.makedirs(repair_dir, exist_ok=True)
                mutation_token(mutation_path, val_code_w2i, val_code_i2w, gen, logger)
                patch, patch_remove = fitness_function(repair_dir, valid_code_path, logger)

                if len(patch_remove) < len(os.listdir(repair_dir)):
                    for remove_contract_path in patch_remove:
                        os.remove(remove_contract_path)
                    break
                elif len(patch_remove) == len(os.listdir(repair_dir)):
                    if len(os.listdir(repair_dir)) == 0:
                        break
                    sorted_list_patch = sorted(patch.items(), key=lambda m: m[1], reverse=True)
                    top15 = dict(sorted_list_patch[:15])
                    for name in os.listdir(repair_dir):
                        remove_contract_path = repair_dir + name
                        if remove_contract_path not in top15.keys():
                            os.remove(remove_contract_path)
                    mutation_path = sorted_list_patch[0][0]

