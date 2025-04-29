#!/bin/env python

# Helper script that makes easy creating a configuration file
# for a sandbox.

import uuid
import argparse
import yaml
import sys
import shlex


def gen_config(
    qemu_cli: list[str],
    snapshot: str,
    run_dir: str,
    distribution: str | None,
    kernel: str | None,
    arch: str | None,
    username: str,
    identity: str,
    kunai_bin=None,
    kunai_args=[],
):
    config = {}
    config["uuid"] = str(uuid.uuid4())
    # qemu configuration
    config["qemu"] = {}
    config["qemu"]["command"] = qemu_cli[0]
    config["qemu"]["args"] = qemu_cli[1:]
    config["qemu"]["snapshot"] = snapshot
    config["qemu"]["run-dir"] = run_dir
    config["qemu"]["distribution"] = (
        "change_me" if distribution is None else distribution
    )
    config["qemu"]["kernel"] = "change_me" if kernel is None else kernel
    config["qemu"]["arch"] = "change_me" if arch is None else arch

    # ssh config
    config["ssh"] = {"username": username, "identity": identity}

    # analysis config (defaults)
    config["analysis"] = {
        "timeout": 60,
        "kunai": {
            "path": "change_me" if kunai_bin is None else kunai_bin,
            "args": kunai_args,
        },
        "tcpdump": {"filter": "! (net 10.0.2.0/24 and port ssh)"},
    }
    return config


def main(argv=None):
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

    config = gen_config(
        qemu_cli,
        args.snapshot,
        args.run_dir,
        args.distribution,
        args.kernel,
        args.arch,
        args.username,
        args.identity,
    )

    yaml.dump(config, sys.stdout, sort_keys=False)


if __name__ == "__main__":
    main()
