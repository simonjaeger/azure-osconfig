# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import sys, subprocess, json, importlib

if len(sys.argv) == 3:
    MODULE_NAME = sys.argv[1]
    ANSIBLE_MODULE_FILE = sys.argv[2]

    module = importlib.import_module('ansible.modules.' + MODULE_NAME)
    args = [sys.executable, "-I", module.__file__, ANSIBLE_MODULE_FILE]

    result = subprocess.run(args, stdout=subprocess.PIPE)
    returncode = result.returncode
    stdout = result.stdout.decode('utf-8') if result.stdout else None
    stderr = result.stderr.decode('utf-8') if result.stderr else None

    if stdout:
        result = json.loads(stdout)
        result.pop("invocation", None)
        result = json.dumps(result)
        print(result, end='')
    else:
        print(stderr or '', end='')

    sys.exit(returncode)