import argparse
import tempfile
import os
import re
import subprocess
import sys
import time
import shutil
import asyncio
import shlex
import yaml

from pathlib import Path
from qemu.qmp import QMPClient
from kunai_sandbox.tools.gen_config import gen_config


def run_qemu_console_command(qmp_sock: Path, command: str):
    return run_qmp_command(qmp_sock, "human-monitor-command", {"command-line": command})


def run_qmp_command(qmp_sock: Path, command: str, arguments: dict | None = None):
    async def _run_qemu_cmd(cmd, arguments=None):
        qmp = QMPClient("QMP shell")
        await qmp.connect(qmp_sock)
        res = await qmp.execute(cmd, arguments)
        await qmp.disconnect()
        return res

    return asyncio.run(_run_qemu_cmd(command, arguments))


def extract_initrd_vmlinuz(image, out_dir):
    """
    This function extract initrd and vmlinuz from a qcow2 image
    It requires the libguestfs library to be installed.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(["guestmount", "-a", image, "-i", "--ro", tmpdir], check=True)

        for path, dirs, files in os.walk(os.path.join(tmpdir, "boot")):
            for file in filter(
                lambda f: any(
                    (
                        f.startswith("vmlinuz"),
                        f.startswith("initrd"),
                        f.startswith("initramfs"),
                    )
                ),
                files,
            ):
                out = Path(out_dir) / file
                with open(out, "wb") as outfd:
                    inp = os.path.join(path, file)
                    with open(inp, "rb") as infd:
                        print(f"copying {inp} -> {out}")
                        shutil.copyfileobj(infd, outfd)

        subprocess.run(["guestunmount", tmpdir], check=True)


def sandbox_init(
    image_path,
    out_dir,
    hostname: str,
    user: str,
    snapshot: str,
    package_upgrade=False,
    kunai_bin=None,
    kunai_args=[],
):
    # we have to reslove it before changing directory
    kunai_bin = str(Path(kunai_bin).resolve()) if kunai_bin is not None else None

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Cleanup stuff
    for file_pattern in ["vmlinuz*", "initr*", "*.qcow2", "*.img"]:
        for file in out_path.glob(file_pattern):
            file.unlink()

    image_file = out_path / Path(image_path).name
    shutil.copy(image_path, image_file)

    arch = None
    if re.search(r"(amd64|x86_64)", image_file.name):
        arch = "x86_64"
    elif re.search(r"(arm64|aarch64)", image_file.name):
        arch = "aarch64"

    if not arch:
        print("Error: target architecture cannot be found")
        sys.exit(1)

    # we change directory
    os.chdir(out_path)

    # Resize qcow2 image
    subprocess.run(["qemu-img", "resize", str(image_file), "60G"], check=True)

    # Extract vmlinuz and initrd
    # subprocess.run([str(extractor), str(image_file)], check=True)
    extract_initrd_vmlinuz(image_file, "./")

    # Prepare SSH settings
    ssh_dir = out_path / "ssh"
    shutil.rmtree(ssh_dir, ignore_errors=True)
    ssh_dir.mkdir(exist_ok=True)
    # Generate SSH key
    subprocess.run(["ssh-keygen", "-N", "", "-f", str(ssh_dir / hostname)], check=True)

    with open(ssh_dir / f"{hostname}.pub") as f:
        ssh_pub_key = " ".join(f.read().strip().split()[:2])

    os_name = image_file.name.split("-")[0]

    # Prepare cloud-init meta-data
    with open(out_path / "meta-data", "w") as f:
        f.write(f"instance-id: {os_name}-instance\n")
        f.write(f"local-hostname: {hostname}\n")

    tmp_user = user.split(":", 1)
    username = tmp_user[0]
    password = tmp_user[1]

    # Prepare cloud-init user-data as a dictionary
    user_data = {
        "package_update": True,
        "package_upgrade": package_upgrade,
        "packages": ["strace", "busybox-static"],
        "users": [
            {
                "name": username,
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "groups": "users, admin",
                "home": f"/home/{username}",
                "shell": "/bin/bash",
                "lock_passwd": False,
                "plain_text_passwd": password,
                "ssh_authorized_keys": [ssh_pub_key],
            }
        ],
        "ssh_pwauth": True,
        "chpasswd": {"list": f"{username}:{password}", "expire": False},
    }

    # Serialize user_data to YAML
    with open(out_path / "user-data", "w") as f:
        f.write("#cloud-config\n")
        yaml.dump(user_data, f, sort_keys=False, indent=2)

    # Generate cloud-init iso
    subprocess.run(
        [
            "xorrisofs",
            "-output",
            "init.iso",
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            "user-data",
            "meta-data",
        ],
        check=True,
    )

    cmdline_linux = os.getenv("CMDLINE_LINUX", "")
    # needed to enable eBPF LSM
    cmdline_linux = (
        f"lsm=lockdown,capability,landlock,yama,apparmor,bpf {cmdline_linux}"
    )

    if arch == "aarch64":
        cpu = os.getenv("CPU", "cortex-a57")
        base_cmd = [
            f"qemu-system-{arch}",
            "-M",
            "virt",
            "-cpu",
            f"{cpu}",
            "-m",
            "4G",
            "-smp",
            "4",
            "-kernel",
            f"{next(out_path.glob('vmlinuz*')).relative_to(out_dir)}",
            "-initrd",
            f"{next(out_path.glob('initr*')).relative_to(out_dir)}",
            "-append",
            f"root=/dev/vda1 {cmdline_linux}",
            "-drive",
            f"file={image_file.name},if=virtio",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-cdrom",
            "init.iso",
            "-boot",
            "d",
            "-nographic",
        ]
    elif arch == "x86_64":
        base_cmd = [
            f"qemu-system-{arch}",
            "-m",
            "4G",
            "-smp",
            "4",
            "-kernel",
            f"{next(out_path.glob('vmlinuz*')).relative_to(out_dir)}",
            "-initrd",
            f"{next(out_path.glob('initr*')).relative_to(out_dir)}",
            "-append",
            f"root=/dev/vda1 console=ttyS0 {cmdline_linux}",
            "-drive",
            f"file={image_file.name},if=virtio",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-cdrom",
            "init.iso",
            "-boot",
            "d",
            "-nographic",
            "-enable-kvm",
        ]

    qmp_sock = "qmp.sock"
    install_log_file = "install.log"
    with open(install_log_file, "w") as fd:
        cmd = base_cmd + [
            "-netdev",
            "user,id=net0",
            "-qmp",
            f"unix:{qmp_sock},server,nowait",
        ]

        subprocess.Popen(
            cmd,
            stdout=fd,
            stderr=fd,
            stdin=subprocess.DEVNULL,
        )

    # Wait for cloud-init target to be finished
    while True:
        with open(install_log_file, "r") as fd:
            if any(
                [re.search("Cloud-init.*finished", line) for line in fd.readlines()]
            ):
                break
        time.sleep(1)

    # Wait 5 additional seconds
    time.sleep(5)

    run_qemu_console_command(qmp_sock, f"savevm {snapshot}")

    snapshots = run_qemu_console_command(qmp_sock, "info snapshots")
    print(snapshots)

    try:
        run_qmp_command(qmp_sock, "quit")
    except EOFError:
        pass

    # Get Linux kernel info
    with open(install_log_file) as install_log_file:
        version_line = next(
            (line for line in install_log_file if "Linux version" in line), None
        )
        if version_line:
            kernel = (
                re.search(r"Linux version (.*?)\s", version_line).group(1).split("-")[0]
            )
            distribution = "change_me"
            if "ubuntu" in version_line.lower():
                distribution = "ubuntu"
            elif "debian" in version_line.lower():
                distribution = "debian"

            identity = str(ssh_dir.relative_to(out_dir) / f"{hostname}")

            base_cmd_with_ports = base_cmd + [
                "-netdev",
                "user,id=net0,hostfwd=tcp::{{ssh-port-fw}}-:22",
                "-object",
                "filter-dump,id=dump,netdev=net0,file={{pcap-file}}",
            ]

            with open("config.yaml", "w") as fd:
                config = gen_config(
                    base_cmd_with_ports,
                    snapshot,
                    "./",
                    distribution,
                    kernel,
                    arch,
                    username,
                    identity,
                    kunai_bin=kunai_bin,
                    kunai_args=kunai_args,
                )
                yaml.dump(config, fd, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(
        description="Prepare a sandbox image with cloud-init.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-H",
        "--hostname",
        default="sandbox",
        help="Hostname of the sandbox.",
    )
    parser.add_argument(
        "-u",
        "--user",
        default="sandbox:password",
        help="User to be created. Format: user:password",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Whether we should run a package upgrade during initialization.",
    )
    parser.add_argument(
        "--snapshot",
        type=str,
        default="ready",
        help="Snapshot name for prepared VM state",
    )
    parser.add_argument("--kunai-bin", type=str, help="Path to kunai binary")
    parser.add_argument(
        "--kunai-args", type=str, help="Kunai args in a single string form"
    )
    parser.add_argument("IMAGE_PATH", help="Path to the QCOW2 image.")
    parser.add_argument("OUT_DIR", help="Output directory.")

    args = parser.parse_args()

    sandbox_init(
        args.IMAGE_PATH,
        args.OUT_DIR,
        args.hostname,
        args.user,
        args.snapshot,
        package_upgrade=args.upgrade,
        kunai_bin=args.kunai_bin,
        kunai_args=[] if args.kunai_args is None else shlex.split(args.kunai_args),
    )


if __name__ == "__main__":
    main()
