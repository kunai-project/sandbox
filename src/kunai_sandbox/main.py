import time
import argparse
import yaml
import os
import gzip
import asyncio
import subprocess
import paramiko
import random
import shlex
import sys
import shutil
import tempfile
import json
import hashlib
import weakref
import signal

from pykunai.graph import KunaiGraph
from pykunai.event import Query, Event, JqDict
from pykunai.misp.export import KunaiMispEvent
from qemu.qmp import QMPClient
from datetime import datetime, timezone


class Sandbox:
    def __init__(self, sandbox_cfg: dict):
        self._sandbox_cfg = sandbox_cfg
        self._qemu_process = None
        _, self._pcap_file = tempfile.mkstemp(prefix="kunai-sandbox-", suffix=".pcap")
        self._ssh_port = random.randint(1025, 65535)
        self._bg_subproc = []
        self.__scp_client = None
        # this is set by main
        self._config_dir = os.path.dirname(sandbox_cfg["path"])
        weakref.finalize(self, self.cleanup)

    def cleanup(self):
        if os.path.isfile(self._pcap_file):
            os.remove(self._pcap_file)

    @property
    def pcap_file(self) -> str:
        return self._pcap_file

    @property
    def qemu_config(self) -> dict:
        return self._sandbox_cfg["qemu"]

    @property
    def ssh_config(self) -> dict:
        return self._sandbox_cfg["ssh"]

    @property
    def ssh_identity(self) -> str:
        return self._resolve_rel_path_to_config(self.ssh_config["identity"])

    @property
    def _qemu_run_dir(self) -> str:
        return self._resolve_rel_path_to_config(self.qemu_config["run-dir"])

    def _resolve_rel_path_to_config(self, path):
        rd = self.qemu_config["run-dir"]
        if os.path.isabs(rd):
            return os.path.join(rd, path)
        else:
            return os.path.realpath(os.path.join(self._config_dir, rd, path))

    def _qemu_rundir_file(self, path) -> str:
        return os.path.join(self._qemu_run_dir, path)

    @property
    def _qmp_sock(self):
        return self._qemu_rundir_file("qmp.sock")

    def _qemu_command(self, loadvm=True):
        _args = list(self.qemu_config["args"])

        for i, arg in enumerate(_args):
            if "{{ssh-port-fw}}" in arg:
                _args[i] = arg.replace("{{ssh-port-fw}}", str(self._ssh_port))

            if "{{pcap-file}}" in arg:
                _args[i] = arg.replace("{{pcap-file}}", self._pcap_file)

        command = [self.qemu_config["command"]]
        command += _args
        if loadvm:
            command.append("-loadvm")
            command.append(self.qemu_config["snapshot"])
        command.append("-qmp")
        command.append(f"unix:{self._qmp_sock},server,nowait")

        return command

    def _ssh_opts(self, uppercase_port: bool):
        p_opt = "-P" if uppercase_port else "-p"
        return [
            "-q",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
            self.ssh_identity,
            p_opt,
            str(self._ssh_port),
        ]

    def _prep_ssh_cmd(self, cmd: str):
        username = self.ssh_config["username"]
        return (
            ["/usr/bin/ssh"]
            + self._ssh_opts(False)
            + [f"{username}@localhost"]
            + shlex.split(cmd)
        )

    def _prep_scp_cmd(self, src: str, dst: str):
        username = self.ssh_config["username"]
        return (
            ["scp"] + self._ssh_opts(True) + [f"{src}", f"{username}@localhost:{dst}"]
        )

    def run_ssh_cmd(self, cmd: str, capture_output=True, check=True):
        return subprocess.run(
            self._prep_ssh_cmd(cmd),
            check=check,
            capture_output=capture_output,
            text=True,
            stdin=subprocess.DEVNULL,
        )

    def bg_ssh_cmd(self, cmd: str, stdout, stderr):
        with (
            open(stdout, "w", encoding="utf8") as out_file,
            open(stderr, "w", encoding="utf8") as err_file,
        ):
            self._bg_subproc.append(
                subprocess.Popen(
                    self._prep_ssh_cmd(cmd),
                    stdin=subprocess.DEVNULL,
                    stdout=out_file,
                    stderr=err_file,
                )
            )

    @property
    def sftp_client(self):
        reset = self.__scp_client is None
        if self.__scp_client is not None:
            reset = self.__scp_client.get_channel().closed

        if reset:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                "localhost",
                username=self.ssh_config["username"],
                port=self._ssh_port,
                key_filename=self.ssh_identity,
            )
            self.__scp_client = ssh_client.open_sftp()

        return self.__scp_client

    def upload_file(self, local: str, remote: str):
        self.sftp_client.put(local, remote)

    def download_file(self, remote: str, local: str):
        """
        This function implement file downloading from SFTP
        server but with file_size limit. If there is no
        file limit and the remote file keeps being written
        at a higher pace than the read, stfp.get never ends.
        """

        # Get file attributes to determine file size
        file_attr = self.sftp_client.stat(remote)
        file_size = file_attr.st_size

        # Open the remote file and the local file
        with (
            self.sftp_client.open(remote, "r") as remote_file,
            open(local, "wb") as local_file,
        ):
            bytes_read = 0
            # Read and write the file in chunks
            while bytes_read < file_size:
                remaining_bytes = file_size - bytes_read
                chunk_size = min((1 << 20) * 4, remaining_bytes)
                chunk = remote_file.read(chunk_size)
                if not chunk:  # End of file
                    break
                local_file.write(chunk)
                bytes_read += len(chunk)

    def start(self, loadvm=True):
        stdout = self._qemu_rundir_file("qemu.stdout")
        stderr = self._qemu_rundir_file("qemu.stderr")

        qemu_cmd = self._qemu_command(loadvm)
        print(" ".join(shlex.quote(arg) for arg in qemu_cmd))

        with (
            open(stdout, "w", encoding="utf8") as out_file,
            open(stderr, "w", encoding="utf8") as err_file,
        ):
            self._qemu_process = subprocess.Popen(
                qemu_cmd,
                stdin=subprocess.DEVNULL,
                stdout=out_file,
                stderr=err_file,
                cwd=self._qemu_run_dir,
            )

        # we wait a bit to make sure qemu runs
        time.sleep(1)

        # qemu command should not fail
        rc = self._qemu_process.poll()
        if rc is not None:
            raise subprocess.CalledProcessError(
                rc, self._qemu_command, f"qemu command failed, inspect {stderr}"
            )

    def dump_utils(self):
        bin_dir = self._qemu_rundir_file("bin")
        os.makedirs(bin_dir, exist_ok=True)

        ssh_util = os.path.join(bin_dir, "ssh")

        with open(ssh_util, "w", encoding="utf8") as fd:
            fd.write("#!/bin/bash\n")
            fd.write(" ".join(self._prep_ssh_cmd("$@")) + "\n")

        os.chmod(ssh_util, 0o0700)

        ssh_opts = " ".join(self._ssh_opts(True))
        cp_to = os.path.join(bin_dir, "cp-to-sbx")

        with open(cp_to, "w", encoding="utf8") as fd:
            fd.write("#!/bin/bash\n")
            cmd = f'scp {ssh_opts} "$1" {self.ssh_config["username"]}@localhost:"$2"'
            fd.write(cmd + "\n")

        os.chmod(cp_to, 0o0700)

        cp_from = os.path.join(bin_dir, "cp-from-sbx")

        with open(cp_from, "w", encoding="utf8") as fd:
            fd.write("#!/bin/bash\n")
            cmd = f'scp {ssh_opts} {self.ssh_config["username"]}@localhost:"$1" "$2"'
            fd.write(cmd + "\n")

        os.chmod(cp_from, 0o0700)

        return [ssh_util, cp_to, cp_from]

    def run_qemu_console_command(self, command: str):
        return self.run_qmp_command("human-monitor-command", {"command-line": command})

    def run_qmp_command(self, command, arguments=None):
        if self._qemu_process.poll() is not None:
            raise Exception("qemu command stopped unexpectedely")

        async def _run_qemu_cmd(cmd, arguments=None):
            qmp = QMPClient("Kunai Sandbox Client")
            await qmp.connect(self._qmp_sock)
            res = await qmp.execute(cmd, arguments)
            await qmp.disconnect()
            return res

        return asyncio.run(_run_qemu_cmd(command, arguments))

    def stop(self):
        # we terminate subprocesses
        for p in self._bg_subproc:
            if p.returncode is None:
                p.terminate()
        try:
            self.run_qmp_command("quit")
        except Exception:
            self._qemu_process.kill()

    def __del__(self):
        try:
            self.stop()
        except Exception:
            pass


def sandbox_stop_no_fail(sbx):
    try:
        sbx.stop()
    except Exception:
        pass


def compress_file(file_path):
    # Define the path for the compressed file
    compressed_file_path = f"{file_path}.gz"

    # Open the original file and the compressed file
    with open(file_path, "rb") as f_in:
        with gzip.open(compressed_file_path, "wb") as f_out:
            # Copy the original file to the compressed file
            shutil.copyfileobj(f_in, f_out)

    # Delete the original file
    os.remove(file_path)


def build_analysis_metadata(sbx, kunai_path, kunai_args, sample_args, timeout):
    meta = {
        "analysis": {},
        "system": {},
        "kunai": {},
        "sample": {},
    }

    meta["analysis"]["timestamp"] = datetime.now(timezone.utc).isoformat()
    meta["analysis"]["duration_sec"] = timeout

    meta["system"]["uname"] = sbx.run_ssh_cmd("uname -a").stdout.strip()
    meta["system"]["kernel"] = sbx.run_ssh_cmd("uname -r").stdout.strip()

    meta["kunai"]["version"] = sbx.run_ssh_cmd(f"{kunai_path} -V").stdout.strip()
    meta["kunai"]["args"] = kunai_args

    meta["sample"]["args"] = sample_args

    return meta


def is_not_none_obj(obj, class_or_tuple):
    if obj is not None:
        return isinstance(obj, class_or_tuple)
    return False


def sha256_file(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def gunzip_events_generator(
    sample_hash: str | None, sample_upload_path: str | None, kunai_log_file: str
):
    with gzip.open(kunai_log_file, "r") as fd:
        q = Query(True)
        if sample_upload_path is not None:
            q.add_exe_path_hit_once([sample_upload_path])
        if sample_hash is not None:
            q.add_hashes([sample_hash])
        for line in fd.readlines():
            event = Event(JqDict(json.loads(line)))
            if q.match(event):
                yield event


def random_task_name():
    # Define the list of strings
    kthreads_names = [
        "card1-crtc",
        "cpuhp",
        "dmcrypt_write",
        "hwrng",
        "idle_inject",
        "iprt",
        "jbd2",
        "kauditd",
        "kcompactd0",
        "kdevtmpfs",
        "khugepaged",
        "khungtaskd",
        "ksgxd",
        "ksmd",
        "ksoftirqd",
        "kswapd0",
        "kthreadd",
        "kworker",
        "migration",
        "oom_reaper",
        "pool_workqueue_release",
        "psimon",
        "rcub",
        "watchdogd",
    ]

    return random.choice(kthreads_names)


class SigtermException(Exception):
    pass


# one can provide argv so that main can be called programatically
def main(argv=None):
    # Function to handle the SIGTERM signal
    def sigterm_handler(signum, frame):
        print("Received SIGTERM. Raising exception...")
        raise SigtermException

    # Set up the signal handler for SIGTERM
    signal.signal(signal.SIGTERM, sigterm_handler)

    if argv is not None:
        sys.argv = [sys.argv[0]] + argv

    parser = argparse.ArgumentParser(
        description="Sandbox runner script",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--copy",
        type=str,
        action="append",
        help="Copy file to VM (expected format /src/path:/dst/path)",
    )
    parser.add_argument(
        "--test", action="store_true", help="Run uname command in sandbox"
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Does nothing but opens an interactive shell in the VM",
    )
    parser.add_argument(
        "--kunai-args",
        type=str,
        help="Additional argument to pass to kunai executable.",
    )
    parser.add_argument("-c", "--config", required=True, help="Sandbox configuration")
    parser.add_argument(
        "--tmp",
        action="store_true",
        help="Duplicates sandbox directory into a temporary directory prior running it",
    )
    parser.add_argument(
        "--tmp-suffix",
        type=str,
        default="",
        help="Suffix to put at the end of temporary files/directory",
    )
    parser.add_argument("-t", "--timeout", type=int, help="Analysis timeout in seconds")
    parser.add_argument("-f", "--force", action="store_true", help="Force analysis")
    parser.add_argument("--strace", action="store_true", help="Strace the sample")
    parser.add_argument("--bpf-logs", action="store_true", help="Strace the sample")
    parser.add_argument(
        "--sync-time", action="store_true", help="Sync time before running kunai"
    )
    parser.add_argument(
        "--compress", action="store_true", help="Compress kunai log file"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        help="Output directory to store analysis results",
    )
    parser.add_argument(
        "--run-as", type=str, default="root", help="Run sample as user. Default: root"
    )
    parser.add_argument(
        "--no-dropped", action="store_true", help="Do not collect dropped files"
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Generate an SVG graph out of sample's activity",
    )
    parser.add_argument(
        "--misp",
        action="store_true",
        help="Generate a MISP event out of sample's activity",
    )
    parser.add_argument(
        "--fix-vm",
        action="store_true",
        help="Attempts at fixing VM failing to load because it was created on another system",
    )
    parser.add_argument("--run", help="Run command (or script) before executing sample")
    parser.add_argument("SAMPLE_COMMAND_LINE", nargs="*")

    args = parser.parse_args()

    ANALYSIS_FILENAME = "analysis.yaml"
    ANALYSIS_PATH = None
    if args.output_dir is not None:
        ANALYSIS_PATH = os.path.join(args.output_dir, ANALYSIS_FILENAME)

    if args.output_dir is not None and not args.force:
        if os.path.isfile(ANALYSIS_PATH):
            print("File has already been analyzed, use -f|--force to analyze it again")
            sys.exit(1)
    elif args.output_dir is not None and args.force and os.path.isdir(args.output_dir):
        shutil.rmtree(args.output_dir)

    tmp_sbx_dir = None
    if args.tmp:
        suffix = f"-{args.tmp_suffix.lstrip('-')}" if args.tmp_suffix != "" else ""
        tmp_sbx_dir = tempfile.TemporaryDirectory(
            prefix="kunai-sandbox-", suffix=f"{suffix}"
        )
        cfg_base = os.path.basename(args.config)
        sbx_dir = os.path.dirname(args.config)
        print(f"creating a temporary sandbox in: {tmp_sbx_dir.name}")
        shutil.copytree(sbx_dir, tmp_sbx_dir.name, dirs_exist_ok=True)
        args.config = os.path.join(tmp_sbx_dir.name, cfg_base)

    # reading config
    with open(args.config, encoding="utf8") as fd:
        config = yaml.safe_load(fd)
    config["path"] = args.config

    analysis_cfg = config["analysis"]
    kunai_cfg = analysis_cfg["kunai"]
    tcpdump_cfg = analysis_cfg["tcpdump"]
    sbx = Sandbox(config)

    # we start the sandbox
    if args.fix_vm:
        print("booting sandbox without snapshot")
        # load VM without snapshot
        sbx.start(loadvm=False)
        # we wait a little time that the sandbox starts
        start = datetime.now()
        snapshot = sbx.qemu_config["snapshot"]
        print("waiting the sandbox to be ready for snapshot")
        # we wait sandbox is ready
        while True:
            try:
                sbx.run_ssh_cmd("uptime")
                break
            except Exception:
                print(
                    f"sandbox hasn't booted yet, time elapsed: {datetime.now() - start}"
                )
                time.sleep(5)

        print("creating snapshot")
        sbx.run_qemu_console_command(f"delvm {snapshot}")
        sbx.run_qemu_console_command(f"savevm {snapshot}")
        sbx.stop()
        sys.exit(0)

    if args.output_dir is None and not args.interactive:
        parser.error("--output-dir must be set for any non-interactive run")

    # we create output directory
    if args.output_dir is not None:
        os.makedirs(args.output_dir, exist_ok=True)

    if args.timeout is not None:
        analysis_cfg["timeout"] = args.timeout

    if args.kunai_args is not None:
        kunai_cfg["args"] = list(
            sorted(set(shlex.split(args.kunai_args) + kunai_cfg["args"]))
        )

    sbx.start()

    # we dump some utility scripts to easily connect to sandbox
    for u in sbx.dump_utils():
        print(f"utility to access your VM: {u}")

    if args.copy is not None:
        for copy in args.copy:
            src, dst = copy.split(":", 2)
            print(f"uploading file to VM: {src} -> {dst}")
            sbx.upload_file(src, dst)

    # run some preparatory commands
    if args.run is not None:
        try:
            if os.path.isfile(args.run):
                tmp_file = os.path.join("/tmp", os.path.basename(args.run))
                sbx.upload_file(args.run, tmp_file)
                sbx.run_ssh_cmd(f"chmod +x {tmp_file}")
                # run as daemon to prevent locking I/O
                subprocess.Popen(
                    sbx._prep_ssh_cmd(f"{tmp_file}"),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                print(f"running command: {args.run}")
                sbx.run_ssh_cmd(args.run)
        except subprocess.CalledProcessError as e:
            # we remove all the SSH command line
            cmd = " ".join(e.cmd).replace(" ".join(sbx._prep_ssh_cmd("")), "")
            print(f"failed to run {cmd}: {e.stderr}")

    if args.sync_time:
        # here we can put the different commands we want to try
        sync_cmds = [
            "sudo systemctl restart systemd-timesyncd",
        ]

        # we attempt at running time sync command but we don't fail
        for cmd in sync_cmds:
            try:
                sbx.run_ssh_cmd(cmd)
                # as soon as a command succeeded we break
                break
            except Exception as e:
                print(f"failed to synchronize time in sandbox: {e}")

    if args.interactive:
        # we need to be sure no other previous command took
        # stdin otherwise we won't see what we type
        subprocess.run(sbx._prep_ssh_cmd(""), check=False)
        sandbox_stop_no_fail(sbx)
        sys.exit(0)

    META = None
    SAMPLE_STDOUT = os.path.join(args.output_dir, "sample.stdout")
    SAMPLE_STDERR = os.path.join(args.output_dir, "sample.stderr")
    KUNAI_LOGS_PATH = os.path.join(args.output_dir, "kunai.jsonl.gz")
    KUNAI_STDERR = os.path.join(args.output_dir, "kunai.stderr")
    PCAP_PATH = os.path.join(args.output_dir, "dump.pcap")
    GRAPH_PATH = os.path.join(args.output_dir, "graph.svg")
    MISP_EVENT_PATH = os.path.join(args.output_dir, "misp-event.json")
    DROPPED_FILES_DIR = os.path.join(args.output_dir, "dropped")
    SAMPLE_UPLOAD_PATH = "/tmp/sample.bin"
    SAMPLE_HASH = None

    # preparing sample
    if args.SAMPLE_COMMAND_LINE:
        SAMPLE_HASH = sha256_file(args.SAMPLE_COMMAND_LINE[0])
        sample_cmd = args.SAMPLE_COMMAND_LINE
        print(f"want to run: {sample_cmd}")
        print(f"uploading: {sample_cmd[0]}")
        sbx.upload_file(sample_cmd[0], SAMPLE_UPLOAD_PATH)
        print("making sample executable")
        sbx.run_ssh_cmd(f"chmod +x {SAMPLE_UPLOAD_PATH}")

        sample_args = sample_cmd[1:] if len(sample_cmd) > 1 else []

    # running kunai
    if kunai_cfg["path"] is not None:
        if not os.path.isfile(kunai_cfg["path"]):
            raise (IOError("kunai is configured but binary is missing"))

        print("uploading kunai binary")
        kunai_tmp_dst = "/tmp/kunai"
        kunai_dst = f"/usr/bin/{random_task_name()}"
        sbx.upload_file(kunai_cfg["path"], kunai_tmp_dst)
        sbx.run_ssh_cmd(f"sudo mv {kunai_tmp_dst} {kunai_dst}")
        sbx.run_ssh_cmd(f"sudo chmod +x {kunai_dst}")

        # good time to dump metadata
        sample_args = sample_args if not args.test else []
        META = build_analysis_metadata(
            sbx, kunai_dst, kunai_cfg["args"], sample_args, analysis_cfg["timeout"]
        )

        str_kunai_args = " ".join(kunai_cfg["args"])

        # trick to prevent being encrypted by cryptolocker
        # we store kunai output within /boot directory
        kunai_stdout = "/boot/kunai.stdout.efi"
        kunai_stderr = "/boot/kunai.stderr.efi"
        full_kunai_cmd = (
            f"sudo {kunai_dst} {str_kunai_args} 1> {kunai_stdout} 2> {kunai_stderr} &"
        )

        # some ransomware samples kill ongoing SSH connection so we
        # better make a runner script to execute kunai and fetch
        # the results later
        with tempfile.NamedTemporaryFile(mode="w") as fd:
            fd.write("#!/bin/bash\n")
            fd.write(f"{full_kunai_cmd}")
            fd.flush()
            sbx.upload_file(fd.name, "/tmp/run.sh")
            sbx.run_ssh_cmd("chmod +x /tmp/run.sh")

        # reading bpf trace pipe
        if args.bpf_logs:
            sbx.bg_ssh_cmd(
                "sudo cat /sys/kernel/debug/tracing/trace_pipe",
                stdout=os.path.join(args.output_dir, "tracepipe.stdout"),
                stderr=os.path.join(args.output_dir, "tracepipe.stderr"),
            )

        print(f"running kunai: {full_kunai_cmd}", flush=True)
        sbx.run_ssh_cmd("sudo /tmp/run.sh", capture_output=False)

        print("waiting kunai to start", flush=True)
        sleep_time = 0
        while True:
            # we try to grep for the start of a kunai event object meaning kunai started
            c = sbx.run_ssh_cmd(
                f"/usr/bin/grep -E '\"data\":' {kunai_stdout}", check=False
            )
            # we found a hit
            if c.returncode == 0:
                break
            if sleep_time > 30:
                print(f"last check command stderr: {c.stderr}")
                raise Exception("kunai took too long to start")
            time.sleep(1)
            sleep_time += 1

        print(f"kunai started in {sleep_time}s")

        # we delete kunai binary and runner script
        sbx.run_ssh_cmd(f"sudo rm {kunai_dst}")
        sbx.run_ssh_cmd("sudo rm /tmp/run.sh")

    if args.test:
        print("running test")
        sbx.bg_ssh_cmd(
            "uname -a",
            stdout=os.path.join(args.output_dir, "test.stdout"),
            stderr=os.path.join(args.output_dir, "test.stderr"),
        )

    if args.SAMPLE_COMMAND_LINE:
        print("running sample")
        str_sample_args = " ".join(sample_args)
        sample_run_cmd = f"sudo -u {args.run_as} {SAMPLE_UPLOAD_PATH} {str_sample_args}"
        if args.strace:
            sample_run_cmd = f"sudo -u {args.run_as} strace -f {SAMPLE_UPLOAD_PATH} {str_sample_args}"

        sbx.bg_ssh_cmd(
            sample_run_cmd,
            stdout=SAMPLE_STDOUT,
            stderr=SAMPLE_STDERR,
        )

    print("waiting analysis to finish: {}s".format(analysis_cfg["timeout"]))
    for i in range(analysis_cfg["timeout"]):
        print(".", end="" if i % 60 != 0 or i == 0 else "\n", flush=True)
        time.sleep(1)
    print()
    print("analysis finished", flush=True)
    print("collecting files", flush=True)

    # we compress output
    sbx.run_ssh_cmd(f"sudo gzip {kunai_stdout}")

    sbx.download_file(f"{kunai_stdout}.gz", KUNAI_LOGS_PATH)
    sbx.download_file(kunai_stderr, KUNAI_STDERR)

    if args.SAMPLE_COMMAND_LINE and not args.no_dropped:
        print("downloading dropped files")
        cache = set()
        for e in gunzip_events_generator(
            SAMPLE_HASH, SAMPLE_UPLOAD_PATH, KUNAI_LOGS_PATH
        ):
            if e["info"]["event"]["name"] == "write_close":
                e_uuid = e["info"]["event"]["uuid"]
                dropped_file = e["data"]["path"]
                if dropped_file in cache:
                    continue
                print(f"\ttrying to download: {dropped_file}")
                os.makedirs(DROPPED_FILES_DIR, exist_ok=True)
                try:
                    # we update cache right now not to reprocess files failure
                    cache.add(dropped_file)
                    try:
                        # some samples are using some LD_PRELOAD tricks so we prefer
                        # using busybox (static) instead of std unix commands
                        sbx.run_ssh_cmd(f"sudo busybox cp {dropped_file} /tmp/d")
                    except subprocess.CalledProcessError as e:
                        # trying to use regular cp but it might be failing
                        sbx.run_ssh_cmd(f"sudo cp {dropped_file} /tmp/d")
                    # we must change some rights if we don't want permission denied
                    sbx.run_ssh_cmd("sudo chmod 777 /tmp/d")

                    if sbx.sftp_client.stat("/tmp/d").st_size > 104_857_600:
                        print("f\taborting file to big")
                        continue

                    local_dir = os.path.join(DROPPED_FILES_DIR, e_uuid)
                    os.makedirs(local_dir)
                    local_file = os.path.join(local_dir, "file.bin")
                    sbx.download_file("/tmp/d", local_file)
                    # removing empty file
                    if os.path.getsize(local_file) == 0:
                        print("\tremoving empty file")
                        shutil.rmtree(local_dir)
                        continue

                    with open(
                        os.path.join(DROPPED_FILES_DIR, e_uuid, "event.json"),
                        "w",
                        encoding="utf8",
                    ) as fd:
                        json.dump(e, fd, indent=2)

                except subprocess.CalledProcessError as e:
                    # we remove all the SSH command line
                    cmd = " ".join(e.cmd).replace(" ".join(sbx._prep_ssh_cmd("")), "")
                    print(f"failed to run {cmd}: {e.stderr}")
                except IOError as e:
                    print(f"failed to fetch dropped file {dropped_file}: {e}")

    sandbox_stop_no_fail(sbx)

    print("processing pcap file", flush=True)
    if is_not_none_obj(tcpdump_cfg["filter"], str):
        tmp_pcap_file = f"{sbx.pcap_file}.tmp"
        subprocess.run(
            [
                "tcpdump",
                "-r",
                sbx.pcap_file,
                "-w",
                tmp_pcap_file,
                tcpdump_cfg["filter"],
            ],
            check=True,
        )
        shutil.move(tmp_pcap_file, PCAP_PATH)
    else:
        shutil.move(sbx.pcap_file, PCAP_PATH)

    print("dumping analysis metadata", flush=True)
    if META is not None:
        with open(ANALYSIS_PATH, "w", encoding="utf8") as fd:
            yaml.dump(META, fd)

    if args.graph and args.output_dir is not None:
        print("generating sample's activity graph", flush=True)
        graph = KunaiGraph()
        graph.from_event_iterator(
            gunzip_events_generator(SAMPLE_HASH, SAMPLE_UPLOAD_PATH, KUNAI_LOGS_PATH)
        )
        graph.to_svg(GRAPH_PATH)

    if args.misp and args.output_dir is not None:
        print("generating MISP event", flush=True)
        events = gunzip_events_generator(
            SAMPLE_HASH, SAMPLE_UPLOAD_PATH, KUNAI_LOGS_PATH
        )
        kunai_misp_event = KunaiMispEvent(events)
        kunai_misp_event.with_sample(args.SAMPLE_COMMAND_LINE[0])
        with open(MISP_EVENT_PATH, "w", encoding="utf8") as fd:
            fd.write(kunai_misp_event.into_misp_event().to_json())

    print("cleaning up", flush=True)
    if os.path.isfile(sbx.pcap_file):
        os.remove(sbx.pcap_file)


if __name__ == "__main__":
    main()
