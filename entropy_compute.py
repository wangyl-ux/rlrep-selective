import os
import re
import subprocess
from antlr4 import *
import solidityparser_compat
from solidityparser.SolidityLexer import SolidityLexer
from solidityparser.SolidityParser import SolidityParser

def get_entropy(contract_path, use_cache, first=None):
    if use_cache == False:
        options = '-ENTROPY -BACKOFF -TEST -FILES'
    else:
        options = '-ENTROPY -BACKOFF -TEST -CACHE -CACHE_ORDER 3 -CACHE_DYNAMIC_LAMBDA -FILE_CACHE -FILES'
    # options_window5000 = '-ENTROPY -BACKOFF -TEST -CACHE -CACHE_ORDER 3 -CACHE_DYNAMIC_LAMBDA -WINDOW_CACHE -WINDOW_SIZE 5000 -FILES'

    completion = os.path.abspath('entropy_compute/code/completion')
    scope_file = os.path.abspath('entropy_compute/data/trainset/fold0.train.scope')
    grams_file = os.path.abspath('entropy_compute/data/trainset/fold0.train.3grams')  # n-grams file

    tmp_dir = "dataset_vul/newALLBUGS/tmp/tmp_function/"
    tmp_test = "dataset_vul/newALLBUGS/tmp/test_function/"
    os.makedirs(tmp_dir, exist_ok=True)
    os.makedirs(tmp_test, exist_ok=True)
    parser_js = os.path.abspath("solidity-extractor/function.js")
    abs_contract_path = os.path.abspath(contract_path)

    cp = subprocess.run(
        ["node", parser_js, abs_contract_path],
        cwd=tmp_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode:
        return -9999
    name = os.path.basename(abs_contract_path)
    tmp_path = os.path.join(tmp_dir, name)
    with open(tmp_path) as f:
        codestring = f.read()

    tree = SolidityParser(CommonTokenStream(SolidityLexer(InputStream(codestring)))).functionDefinition()
    output = tree.toCodeSequence()
    regex = r'(\[)[0-9\s]*(\])'
    output2 = re.sub(regex, '', output)
    output3 = output2.split(' ')
    tokens = [char for char in output3 if char != '' and char != '<EOF>']
    sourceCode = " ".join(tokens)
    with open(tmp_path, 'w') as f:
        f.write(sourceCode)

    test_file = os.path.join(tmp_test, name)
    with open(test_file, 'w') as f2:
        f2.write(tmp_path)

    # compute entropy
    if not os.path.exists(completion) or not os.access(completion, os.X_OK):
        return -9999
    order = 3
    cp2 = subprocess.run(
        [completion] + options.split() + ['-NGRAM_FILE', grams_file, '-NGRAM_ORDER', str(order), '-SCOPE_FILE', scope_file, '-INPUT_FILE', test_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp2.returncode:
        return -9999
    lines = cp2.stdout.decode().split('\n')
    for line in lines:
        if 'Entropy: ' in line:
            return float(line.strip('Entropy: '))


if __name__ == '__main__':
    pass
