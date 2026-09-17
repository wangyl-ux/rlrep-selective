import argparse
from utils2 import *
from genetic import *
from collections import Counter
import os
import pickle
import re
import sys
import json

from preprocessing.selective_context import prepare_context_directory
from preprocessing.context_config import (
    DEFAULT_RULE_VERSION,
    DEFAULT_SLITHER_IMAGE,
    SUPPORTED_RULE_VERSIONS,
    build_context_config,
    validate_checkpoint_context,
)

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
    detect_skipped = sum(detail.get('detect_skipped', 0) for detail in reward_details)
    detect_original_fail = sum(detail.get('detect_original_fail', 0) for detail in reward_details)
    detect_repair_fail = sum(detail.get('detect_repair_fail', 0) for detail in reward_details)
    similarity_used = sum(detail.get('similarity_used', 0) for detail in reward_details)
    entropy_used = sum(detail.get('entropy_used', 0) for detail in reward_details)
    compile_reward = sum(detail.get('compile_reward', 0.0) for detail in reward_details)
    detect_reward = sum(detail.get('detect_reward', 0.0) for detail in reward_details)
    similarity_reward = sum(detail.get('similarity_reward', 0.0) for detail in reward_details)
    entropy_reward = sum(detail.get('entropy_reward', 0.0) for detail in reward_details)
    action_reward = sum(detail.get('action_reward', 0.0) for detail in reward_details)
    positive = sum(1 for reward in rewards if reward > 0)
    zero_or_negative = total - positive
    original_fail_tools = Counter()
    repair_fail_tools = Counter()

    def format_counter(counter):
        if not counter:
            return 'none'
        return ','.join('{}:{}'.format(key, counter[key]) for key in sorted(counter))

    def format_detect_side(detail, side):
        status = detail.get('detect_{}_status'.format(side), '') or 'none'
        tool = detail.get('detect_{}_tool'.format(side), '')
        reason = detail.get('detect_{}_reason'.format(side), '')
        if tool and reason:
            return '{}({}:{})'.format(status, tool, reason)
        if tool:
            return '{}({})'.format(status, tool)
        if reason:
            return '{}({})'.format(status, reason)
        return status

    for detail in reward_details:
        if detail.get('detect_original_fail', 0):
            key = '{}:{}'.format(
                detail.get('detect_original_tool', '') or 'unknown',
                detail.get('detect_original_reason', '') or 'unknown',
            )
            original_fail_tools[key] += 1
        if detail.get('detect_repair_fail', 0):
            key = '{}:{}'.format(
                detail.get('detect_repair_tool', '') or 'unknown',
                detail.get('detect_repair_reason', '') or 'unknown',
            )
            repair_fail_tools[key] += 1

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
        'detect skipped. epoch: {}. total: {}, original_fail: {}, repair_fail: {}, original_tool_fail: {}, repair_tool_fail: {}'.format(
            epoch,
            detect_skipped,
            detect_original_fail,
            detect_repair_fail,
            format_counter(original_fail_tools),
            format_counter(repair_fail_tools),
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
            'candidate reward. epoch: {}. contract: {}. total: {:.6f}, compile: {:.6f}, detect: {:.6f}, similarity: {:.6f}, entropy: {:.6f}, action: {:.6f}, status: {}, detect_skip: {}, original_detect: {}, repair_detect: {}'.format(
                epoch,
                detail.get('contract', 'unknown'),
                detail.get('reward', 0.0),
                detail.get('compile_reward', 0.0),
                detail.get('detect_reward', 0.0),
                detail.get('similarity_reward', 0.0),
                detail.get('entropy_reward', 0.0),
                detail.get('action_reward', 0.0),
                detail.get('status', 'unknown'),
                detail.get('detect_skipped', 0),
                format_detect_side(detail, 'original'),
                format_detect_side(detail, 'repair'),
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


def parse_resume_request(argv):
    if len(argv) <= 3:
        return 'auto', ''
    raw_value = argv[3].strip()
    lowered = raw_value.lower()
    if lowered in ('fresh', 'scratch', 'from_scratch', 'restart', 'never', 'noresume'):
        return 'never', ''
    if lowered in ('resume', 'auto', 'latest'):
        return 'auto', ''
    if raw_value.startswith('resume='):
        return 'path', raw_value[len('resume='):]
    if raw_value.startswith('checkpoint='):
        return 'path', raw_value[len('checkpoint='):]
    return 'path', raw_value


def resolve_resume_behavior(model_dir, model_name, argv, logger):
    cli_mode, cli_path = parse_resume_request(argv)
    env_mode = os.environ.get('RLREP_RESUME_MODE', '').strip().lower()
    env_path = os.environ.get('RLREP_RESUME_PATH', '').strip()

    resume_mode = cli_mode
    resume_path = cli_path

    if env_mode:
        if env_mode in ('fresh', 'scratch', 'from_scratch', 'restart', 'never', 'noresume', 'false', '0'):
            resume_mode = 'never'
            resume_path = ''
        elif env_mode in ('resume', 'auto', 'latest', 'true', '1'):
            resume_mode = 'auto'
            resume_path = ''
        elif env_mode in ('path', 'explicit'):
            resume_mode = 'path'
        else:
            logger.warning('Unknown RLREP_RESUME_MODE=%s, fallback to CLI/default mode=%s', env_mode, resume_mode)

    if env_path:
        resume_mode = 'path'
        resume_path = env_path

    if resume_mode == 'never':
        logger.info('Resume mode: fresh start (ignore checkpoints)')
        return None, -1

    if resume_mode == 'path':
        if not resume_path:
            raise ValueError('Resume mode "path" requires a checkpoint path')
        resume_path = os.path.abspath(resume_path)
        if not os.path.exists(resume_path):
            raise FileNotFoundError('Resume checkpoint not found: {}'.format(resume_path))
        matched = re.search(r'_train_epoch_(\d+)\.pt$', os.path.basename(resume_path))
        resume_epoch = int(matched.group(1)) if matched else -1
        logger.info('Resume mode: explicit checkpoint ({})'.format(resume_path))
        return resume_path, resume_epoch

    resume_path, resume_epoch = find_latest_train_checkpoint(model_dir, model_name)
    if resume_path is not None:
        logger.info('Resume mode: auto latest checkpoint ({})'.format(resume_path))
    else:
        logger.info('Resume mode: auto, but no checkpoint found; start from scratch')
    return resume_path, resume_epoch


def parse_main_args():
    parser = argparse.ArgumentParser(description='Train RLRep or run the mutation baseline.')
    parser.add_argument('model_name', help='multistep_RLRep or mutation')
    parser.add_argument('dataset_path', help='dataset path, usually dataset_vul/newALLBUGS')
    parser.add_argument('resume', nargs='?', default='', help='optional legacy resume argument')
    parser.add_argument(
        '--context-mode',
        '--context_mode',
        dest='context_mode',
        choices=('original', 'selective', 'selective_v1', 'evidence_graph'),
        default='original',
        help='original keeps RLRep 3-line context; selective/selective_v1 retain the old selector; evidence_graph reads offline Slither contexts',
    )
    parser.add_argument(
        '--metadata-csv',
        '--metadata_csv',
        dest='metadata_csv',
        default='',
        help='optional metadata csv override for selective/evidence_graph context',
    )
    parser.add_argument('--context-token-budget', type=int, default=64)
    parser.add_argument('--context-max-nodes', type=int, default=8)
    parser.add_argument('--context-max-hops', type=int, default=2)
    parser.add_argument('--context-fallback', choices=('selective_v1', 'original'), default='selective_v1')
    parser.add_argument('--context-rule-version', choices=SUPPORTED_RULE_VERSIONS, default=DEFAULT_RULE_VERSION)
    parser.add_argument('--slither-image', default=DEFAULT_SLITHER_IMAGE)
    parser.add_argument(
        '--allow-legacy-context-checkpoint', action='store_true',
        help='explicitly allow an unverifiable legacy checkpoint with evidence_graph')
    args = parser.parse_args()
    if args.context_token_budget < 1 or args.context_max_nodes < 1 or args.context_max_hops < 0:
        parser.error('context token/node budgets must be positive and max hops cannot be negative')
    return args


if __name__ == "__main__":
    args = parse_main_args()
    model_name = args.model_name  # "multistep_RLRep" or "mutation"
    path = args.dataset_path  # "dataset_vul/newALLBUGS"
    resume_argv = ['main.py', model_name, path]
    if args.resume:
        resume_argv.append(args.resume)
    
    logger = get_logger('dataset_vul/newALLBUGS/log/{}_logging.txt'.format(model_name))
    logger.info('context mode: %s. metadata csv override: %s', args.context_mode, args.metadata_csv or '<default>')
    context_config = build_context_config(
        args.context_mode,
        args.context_token_budget,
        args.context_max_nodes,
        args.context_max_hops,
        args.context_fallback,
        args.slither_image,
        args.context_rule_version,
    )
    logger.info('context_config=%s', json.dumps(context_config, sort_keys=True))
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
        resume_path, resume_epoch = resolve_resume_behavior(model_dir, model_name, resume_argv, logger)
        if resume_path is not None:
            checkpoint = model.load(resume_path)
            validate_checkpoint_context(
                checkpoint, context_config, logger=logger, purpose='training resume',
                allow_legacy_evidence=args.allow_legacy_context_checkpoint)
            start = checkpoint.get('epoch', resume_epoch)
            best_positive_repair = checkpoint.get('best_positive_repair', best_positive_repair)
            logger.info('Resume checkpoint: {} (epoch={})'.format(resume_path, start))
        elif start != -1:
            model.load('dataset_vul/newALLBUGS/model/multistep_RLRep_33')
            model.set_trainer()

        pretrain_contract_dir = os.path.join(path, 'contract')
        train_contract_dir = os.path.join(path, 'contract')
        validation_contract_dir = os.path.join(path, 'validation', 'contract')
        pretrain_code_dir = prepare_context_directory(
            path,
            os.path.join(path, 'pretrain', 'threelines-tokenseq'),
            pretrain_contract_dir,
            'pretrain',
            context_mode=args.context_mode,
            metadata_csv=args.metadata_csv,
            logger=logger,
            context_config=context_config,
        )
        train_code_dir = prepare_context_directory(
            path,
            os.path.join(path, 'threelines-tokenseq'),
            train_contract_dir,
            'train',
            context_mode=args.context_mode,
            metadata_csv=args.metadata_csv,
            logger=logger,
            context_config=context_config,
        )
        validation_code_dir = prepare_context_directory(
            path,
            os.path.join(path, 'validation', 'threelines-tokenseq'),
            validation_contract_dir,
            'validation',
            context_mode=args.context_mode,
            metadata_csv=args.metadata_csv,
            logger=logger,
            context_config=context_config,
        )

        for epoch in range(start+1, config.PRE_EPOCH):
            loss = 0
            code_dir = pretrain_code_dir
            ast_dir = 'dataset_vul/newALLBUGS/pretrain/ast'
            for step, batch in enumerate(get_batch(code_dir, ast_dir, config, in_w2i, pretrain=True)):
                batch_in1, batch_in2, batch_in3, batch_out = batch
                loss += model.pretrain(batch[:-2], batch[-1], 'actor')
                logger.info('Epoch: {}, Batch: {}, Loss: {}'.format(epoch, step, loss / (step + 1)))
            # Old behavior saved a full checkpoint every pretrain epoch.
            # model.save('dataset_vul/newALLBUGS/model/{}_{}'.format(model_name, epoch))
            if (epoch + 1) % checkpoint_every == 0:
                model.save(get_periodic_checkpoint_path(model_dir, model_name, epoch), epoch=epoch, best_positive_repair=best_positive_repair, context_config=context_config)

        train_start_epoch = max(config.PRE_EPOCH, start + 1)
        for epoch in range(train_start_epoch, config.EPOCH):
            loss_actor = 0
            loss_critic = 0.
            code_dir = train_code_dir
            ast_dir = 'dataset_vul/newALLBUGS/ast'
            for step, batch in enumerate(get_batch(code_dir, ast_dir, config, in_w2i, pretrain=False)):
                batch_in1, batch_in2, batch_in3 = batch
                loss = model(batch[:-1], True, batch[-1])
                loss_actor += loss
                logger.info('Epoch: {}, Batch: {}, Loss: actor:{}'.format(epoch, step, loss_actor / (step + 1),))

            preds, ats, names, rewards, reward_details = [], [], [], [], []
            valid_code_dir = validation_code_dir
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
                        'detect_skipped': 0,
                        'detect_original_fail': 0,
                        'detect_repair_fail': 0,
                        'detect_original_tool': '',
                        'detect_original_reason': '',
                        'detect_original_status': '',
                        'detect_repair_tool': '',
                        'detect_repair_reason': '',
                        'detect_repair_status': '',
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
                        'detect_skipped': 0,
                        'detect_original_fail': 0,
                        'detect_repair_fail': 0,
                        'detect_original_tool': '',
                        'detect_original_reason': '',
                        'detect_original_status': '',
                        'detect_repair_tool': '',
                        'detect_repair_reason': '',
                        'detect_repair_status': '',
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
                model.save(os.path.join(model_dir, '{}_{}'.format(model_name, epoch)), epoch=epoch, best_positive_repair=best_positive_repair, context_config=context_config)
            else:
                print('model NOT update. the {0}-th epoch. positive reward / total : {1} / {2}, mean reward: {3:.6f}'.format(epoch, positive_repair, len(names), mean_reward))
            if (epoch + 1) % checkpoint_every == 0:
                model.save(get_periodic_checkpoint_path(model_dir, model_name, epoch), epoch=epoch, best_positive_repair=best_positive_repair, context_config=context_config)

                
    if model_name == 'mutation':
        if args.context_mode != 'original':
            logger.warning('context mode %s is ignored by the mutation baseline', args.context_mode)
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

