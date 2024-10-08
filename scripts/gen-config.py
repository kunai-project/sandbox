#!/bin/env python

# Helper script that makes easy creating a configuration file
# for a sandbox.

import argparse
import yaml
import sys
import shlex

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--snapshot", required=True)
    parser.add_argument("-r", "--run-dir", required=True)
    parser.add_argument("COMMAND_LINE", nargs='*')

    args = parser.parse_args()

    # this is needed to process correctly -append in qemu CLI
    qemu_cli = shlex.split(" ".join(args.COMMAND_LINE))
    config = {}
    config["qemu"] = {}
    config["qemu"]["command"] = qemu_cli[0]
    config["qemu"]["args"] = qemu_cli[1:]
    config["qemu"]["snapshot"] = args.snapshot
    config["qemu"]["run-dir"] = args.run_dir
    config["qemu"]["distribution"] = "change_me"

    yaml.dump(config, sys.stdout, sort_keys=False)