#!/bin/env python

# Helper script that makes easy creating a configuration file
# for a sandbox.

import uuid
import argparse
import yaml
import sys
import shlex


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--arch", type=str, help="Architecture of the VM")
    parser.add_argument(
        "-d", "--distribution", type=str, help="Distribution of the sandbox"
    )
    parser.add_argument(
        "-k", "--kernel", type=str, help="Kernel version of the sandbox"
    )
    parser.add_argument("-u", "--username", type=str, required=True, help="Username")
    parser.add_argument(
        "-i",
        "--identity",
        required=True,
        type=str,
        help="Path to SSH identity",
    )
    parser.add_argument("-s", "--snapshot", required=True)
    parser.add_argument("-r", "--run-dir", required=True)
    parser.add_argument("COMMAND_LINE", nargs="*")

    args = parser.parse_args()

    # this is needed to process correctly -append in qemu CLI
    qemu_cli = shlex.split(" ".join(args.COMMAND_LINE))
    config = {}
    config["uuid"] = str(uuid.uuid4())
    # qemu configuration
    config["qemu"] = {}
    config["qemu"]["command"] = qemu_cli[0]
    config["qemu"]["args"] = qemu_cli[1:]
    config["qemu"]["snapshot"] = args.snapshot
    config["qemu"]["run-dir"] = args.run_dir
    config["qemu"]["distribution"] = (
        "change_me" if args.distribution is None else args.distribution
    )
    config["qemu"]["kernel"] = "change_me" if args.kernel is None else args.kernel
    config["qemu"]["arch"] = "change_me" if args.arch is None else args.arch

    # ssh config
    config["ssh"] = {"username": args.username, "identity": args.identity}

    # analysis config (defaults)
    config["analysis"] = {
        "timeout": 60,
        "kunai": {"path": "change_me", "args": []},
        "tcpdump": "! (net 10.0.2.0/24 and port ssh)",
    }

    yaml.dump(config, sys.stdout, sort_keys=False)


if __name__ == "__main__":
    main()
