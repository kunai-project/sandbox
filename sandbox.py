#!/bin/env python

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

from qemu.qmp import QMPClient
from datetime import datetime, timezone

class Sandbox:

    def __init__(self, sandbox_cfg: dict):
        self._sandbox_cfg = sandbox_cfg
        self._qemu_process = None
        _, self._pcap_file = tempfile.mkstemp()
        self._ssh_port = random.randint(1025, 65535)
        self._bg_subproc = []
        self.__scp_client = None

    @property
    def pcap_file(self):
        return self._pcap_file

    @property
    def qemu_config(self):
        return self._sandbox_cfg["qemu"]

    @property
    def ssh_config(self):
        return self._sandbox_cfg["ssh"]
    
    def _qemu_rundir_file(self, path):
        return os.path.join(os.path.realpath(self.qemu_config["run-dir"]), path)

    @property
    def _qmp_sock(self):
        return self._qemu_rundir_file("qmp.sock")

    @property
    def _qemu_command(self):
        _args = list(self.qemu_config["args"])

        for i, arg in enumerate(_args):
            if "{{ssh-port-fw}}" in arg:
                _args[i] = arg.replace("{{ssh-port-fw}}", str(self._ssh_port))

            if "{{pcap-file}}" in arg:
                _args[i] = arg.replace("{{pcap-file}}", self._pcap_file)

        command = [self.qemu_config["command"]]
        command += _args
        command.append("-loadvm")
        command.append(self.qemu_config["snapshot"])
        command.append("-qmp")
        command.append(f"unix:{self._qmp_sock},server,nowait")
        
        return command
    
    def ssh_opts(self, uppercase_port: bool):
        p_opt = "-P" if uppercase_port else "-p"
        return [
            "-q", 
            "-o", 
            "StrictHostKeyChecking=no", 
            "-o", 
            "UserKnownHostsFile=/dev/null",
            "-i", self.ssh_config["identity"],
            p_opt, str(self._ssh_port),
        ]
    
    def prep_ssh_cmd(self, cmd: str):
        return ["/usr/bin/ssh"] + self.ssh_opts(False) + [f"{self.ssh_config["username"]}@localhost"] + shlex.split(cmd)
    
    def prep_scp_cmd(self, src: str, dst: str):
        return ["scp"] + self.ssh_opts(True) + [
            f"{src}",
            f"sandbox@localhost:{dst}"
        ]
    
    def run_ssh_cmd(self, cmd: str):
        return subprocess.run(self.prep_ssh_cmd(cmd), check=True, capture_output=True, text=True)

    def bg_ssh_cmd(self, cmd: str, stdout, stderr):
        with open(stdout, 'w', encoding="utf8") as out_file, open(stderr, 'w', encoding="utf8") as err_file:
            self._bg_subproc.append(subprocess.Popen(self.prep_ssh_cmd(cmd),stdout=out_file, stderr=err_file))
            
    @property
    def _scp_client(self):
        reset = self.__scp_client is None
        if self.__scp_client is not None:
            reset = self.__scp_client.get_channel().closed

        if reset:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect("localhost", username=self.ssh_config["username"], port=self._ssh_port, key_filename=self.ssh_config["identity"])
            self.__scp_client = ssh_client.open_sftp()
        return self.__scp_client

    def upload_file(self, local: str, remote: str):
        self._scp_client.put(local, remote)
    
    def download_file(self, remote: str, local: str):
        self._scp_client.get(remote, local)

    def start(self):
        stdout = self._qemu_rundir_file("qemu.stdout")
        stderr = self._qemu_rundir_file("qemu.stderr")

        print(" ".join(self._qemu_command))

        with open(stdout, 'w', encoding="utf8") as out_file, open(stderr, 'w', encoding="utf8") as err_file:
            self._qemu_process = subprocess.Popen(self._qemu_command, stdin=subprocess.DEVNULL ,stdout=out_file, stderr=err_file)

        # we wait a bit to make sure qemu runs
        time.sleep(1)

        # qemu command should not fail
        if self._qemu_process.poll() is not None:
            raise Exception(f"qemu command failed, inspect {stderr}")
    
    def dump_utils(self):
        bin_dir = self._qemu_rundir_file("bin")
        os.makedirs(bin_dir, exist_ok=True)

        ssh_util = os.path.join(bin_dir, "ssh")

        with open(ssh_util, 'w', encoding="utf8") as fd:
            fd.write("#!/bin/bash\n")
            fd.write(" ".join(self.prep_ssh_cmd("$@")) + "\n")
        
        os.chmod(ssh_util, 0o0700)

        scp_util = os.path.join(bin_dir, "scp")

        with open(scp_util, 'w', encoding="utf8") as fd:
            fd.write("#!/bin/bash\n")
            fd.write(" ".join(self.prep_scp_cmd('"$1"', '"$2"')) + "\n")
        
        os.chmod(scp_util, 0o0700)

        return [ssh_util, scp_util]


    
    def run_qemu_command(self, command):
        if self._qemu_process.poll() is not None:
            raise Exception(f"qemu command stopped unexpectedely, inspect {stderr}")

        async def _run_qemu_cmd(cmd):
            qmp = QMPClient('blah')
            await qmp.connect(self._qmp_sock)
            res = await qmp.execute(cmd)
            await qmp.disconnect()
            return res
        return asyncio.run(_run_qemu_cmd(command))

    def stop(self):
        # we terminate subprocesses 
        for p in self._bg_subproc:
            if p.returncode is None:
                p.terminate()
        self.run_qemu_command("quit")
    
def sandbox_stop_no_fail(sbx):
    try:
        sbx.stop()
    except:
        pass

def compress_file(file_path):
    # Define the path for the compressed file
    compressed_file_path = f"{file_path}.gz"
    
    # Open the original file and the compressed file
    with open(file_path, 'rb') as f_in:
        with gzip.open(compressed_file_path, 'wb') as f_out:
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

if __name__ == "__main__":
    ANALYSIS_FILENAME = "analysis.yaml"
    KUNAI_LOG_FILENAME = "kunai.jsonl"

    parser = argparse.ArgumentParser(description="Sandbox runner script")
    parser.add_argument("--copy", type=str, action="append", help="Copy file to VM (expected format /src/path:/dst/path)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Does nothing but opens an interactive shell in the VM")
    parser.add_argument("--kunai-args", type=str, help="Additional argument to pass to kunai executable.")
    parser.add_argument("-c", "--config", required=True,  help="Sandbox configuration")
    parser.add_argument("-t", "--timeout", type=int, help="Analysis timeout in seconds")
    parser.add_argument("-f", "--force", action="store_true", help="Force analysis")
    parser.add_argument("--strace", action="store_true", help="Strace the sample")
    parser.add_argument("--bpf-logs", action="store_true", help="Strace the sample")
    parser.add_argument("-o", "--output-dir", type=str, help="Output directory to store analysis results" )
    parser.add_argument("--run-as", type=str, default="root", help="Run sample as user. Default: root" )
    parser.add_argument("SAMPLE_COMMAND_LINE", nargs="*")

    args = parser.parse_args()

    if args.output_dir is not None and not args.force and os.path.isfile(os.path.join(args.output_dir, ANALYSIS_FILENAME)):
        print("File has already been analyzed, use -f|--force to analyze it again")
        sys.exit(1)

    # reading config
    with open(args.config, encoding="utf8") as fd:
        config = yaml.safe_load(fd)

    analysis_cfg = config["analysis"]
    kunai_cfg = analysis_cfg["kunai"]
    tcpdump_cfg = analysis_cfg["tcpdump"]
    sbx = Sandbox(config)

    # we create output directory
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
    
    if args.timeout is not None:
        analysis_cfg["timeout"] = args.timeout
    
    if args.kunai_args is not None:
        kunai_cfg["args"] = list(sorted(set(shlex.split(args.kunai_args) + kunai_cfg["args"])))

    # we start the sandbox
    sbx.start()

    try:
        # we dump some utility scripts to easily connect to sandbox   
        for u in sbx.dump_utils():
            print(f"utility to access your VM: {u}")

        if args.copy is not None:
            for copy in args.copy:
                src, dst = copy.split(":", 2)
                print(f"uploading file to VM: {src} -> {dst}")
                sbx.upload_file(src, dst)

        if args.interactive:
            # we need to be sure no other previous command took
            # stdin otherwise we won't see what we type
            subprocess.run(sbx.prep_ssh_cmd(""))
            sandbox_stop_no_fail(sbx)
            sys.exit(0)

        META = None
        kunai_ouptut = os.path.join(args.output_dir, KUNAI_LOG_FILENAME)

        # preparing sample
        if args.SAMPLE_COMMAND_LINE:
            sample_cmd = args.SAMPLE_COMMAND_LINE
            print(f"want to run: {sample_cmd}")
            print(f"uploading: {sample_cmd[0]}")
            sbx.upload_file(sample_cmd[0], "/tmp/sample.bin")
            print("making sample executable")
            sbx.run_ssh_cmd("chmod +x /tmp/sample.bin")

            sample_args = sample_cmd[1:] if len(sample_cmd) > 1 else []

        # running kunai
        if kunai_cfg["path"] is not None:
            if not os.path.isfile(kunai_cfg["path"]):
                raise(IOError("kunai is configured but binary is missing"))

            print("uploading kunai binary")
            kunai_tmp_dst = "/tmp/kunai"
            kunai_dst = "/usr/bin/tcpdumb"
            sbx.upload_file(kunai_cfg["path"], kunai_tmp_dst)
            sbx.run_ssh_cmd(f"sudo mv {kunai_tmp_dst} {kunai_dst}")
            sbx.run_ssh_cmd(f"sudo chmod +x {kunai_dst}")
            
            # good time to dump metadata
            META = build_analysis_metadata(sbx, kunai_dst, kunai_cfg["args"], sample_args, analysis_cfg["timeout"])

            str_kunai_args = " ".join(kunai_cfg["args"])

            full_kunai_cmd = f"sudo {kunai_dst} {str_kunai_args} 1> /boot/kunai.stdout.efi 2> /boot/kunai.stderr.efi &"

            with tempfile.NamedTemporaryFile(mode="w") as fd:
                fd.write("#!/bin/bash\n")
                fd.write(f"{full_kunai_cmd}")
                fd.flush()
                sbx.upload_file(fd.name, "/tmp/run.sh")
                sbx.run_ssh_cmd("chmod +x /tmp/run.sh")

            print(f"running kunai: {full_kunai_cmd}")
            #sbx.bg_ssh_cmd(full_kunai_cmd,
                #stdout=kunai_ouptut,
                #stderr=os.path.join(args.output_dir,"kunai.stderr"))
            sbx.run_ssh_cmd("sudo /tmp/run.sh")

            print("waiting kunai to start")
            if args.bpf_logs:
                sbx.bg_ssh_cmd("sudo cat /sys/kernel/debug/tracing/trace_pipe",
                    stdout=os.path.join(args.output_dir, "tracepipe.stdout"),
                    stderr=os.path.join(args.output_dir, "tracepipe.stderr"))
            time.sleep(5)

        if args.SAMPLE_COMMAND_LINE:
            
            print("running sample")
            str_sample_args = " ".join(sample_args)
            sample_run_cmd = f"sudo -u {args.run_as} /tmp/sample.bin {str_sample_args}"
            if args.strace:
                sample_run_cmd = f"sudo -u {args.run_as} strace -f /tmp/sample.bin {str_sample_args}"

            sbx.bg_ssh_cmd(sample_run_cmd, 
                stdout=os.path.join(args.output_dir,"sample.stdout"),
                stderr=os.path.join(args.output_dir,"sample.stderr"))
        

        print("waiting analysis to finish: {}s".format(analysis_cfg["timeout"]))
        for i in range(analysis_cfg["timeout"]):
            print(".", end="" if i % 60 != 0 or i == 0 else "\n", flush=True)
            time.sleep(1)
        print()
        print("analysis finished")
        print("collecting files")

        sbx.download_file("/boot/kunai.stdout.efi", kunai_ouptut)
        sbx.download_file("/boot/kunai.stderr.efi", os.path.join(args.output_dir,"kunai.stderr"))
        sandbox_stop_no_fail(sbx)

        print("processing pcap file")
        tmp = f"{sbx.pcap_file}.tmp"
        subprocess.run(["tcpdump", "-r", sbx.pcap_file, "-w", tmp, tcpdump_cfg["filter"]], check=True)
        shutil.move(tmp, os.path.join(args.output_dir, "dump.pcap"))

        print("dumping analysis metadata")
        if META is not None:
            with open(os.path.join(args.output_dir, ANALYSIS_FILENAME), "w") as fd:
                yaml.dump(META, fd)

        print("cleaning up")
        os.remove(sbx.pcap_file)

    except Exception as e:
        # whatever happens we stop sandbox
        sandbox_stop_no_fail(sbx)
        raise e



    
