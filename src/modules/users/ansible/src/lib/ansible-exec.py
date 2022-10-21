# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import sys, subprocess, json, importlib

MODULE_NAME = sys.argv[1]

module = importlib.import_module('ansible.modules.' + MODULE_NAME)
args = [sys.executable, "-I", module.__file__]

if len(sys.argv) > 1:
    args.extend(sys.argv[2:])

result = subprocess.run(args, stdout=subprocess.PIPE)
stdout = result.stdout.decode('utf-8') if result.stdout else None
stderr = result.stderr.decode('utf-8') if result.stderr else None

if stdout:
    result = json.loads(stdout)
    result.pop("invocation", None)
    print(result)
else:
    print(stderr or '')