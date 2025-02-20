# Kunai Sandbox

This project hosts a platform for sandboxing and analyzing malware samples using [Kunai](https://github.com/kunai-project/kunai). It is designed to support sandbox environments for both **x86_64** and **aarch64** architectures, enabling users to safely isolate malware samples and generate real-world data for threat analysis.

A key feature is the generation of detailed Kunai traces and network traffic dumps, providing detection engineers with direct access to critical insights such as behavioral patterns, system-level activities, and network interactions. This actionable data simplifies the creation of detection rules and significantly accelerates the development of effective defenses against emerging threats.

To have an idea of the data which can be collected with this platform, please visit: https://helga.circl.lu/NGSOTI/malware-dataset

# How to use ?

## Installation

This section assumes you already used pipx/uv and that installation directory is in your `PATH` environment variable.

### Using `uv`

```bash
# installation
uv tool install https://github.com/kunai-project/sandbox.git

# testing
kunai-sandbox -h
# tool used to generate sandbox config
ks-gen-config -h
```

### Using `pipx`

```bash
# installation
pipx install git+https://github.com/kunai-project/sandbox.git

# testing
kunai-sandbox -h
# tool used to generate sandbox config
ks-gen-config -h
```

## Preparing VMs

Make sure you are running the follwing scripts and command **from within
the virtual environment** you have created.

### 1. download working image(s)

```bash
# this would download SEVERAL known working qemu images from debian/ubuntu repositories
./scripts/download-images.sh
```
**NB:** alternatively you can take a download link in that script and download the file

### 2. initializing the sandbox 

```bash
./scripts/sandbox-init.sh /path/to/qcow/image /path/to/prepared/sandbox
```

This initialization takes more or less time depending if you are relying on full system emulation or if you benefit from KVM acceleration.
Anyway, you must wait for the script to terminate before going further.

### 3. adjust sandbox configuration file

```bash
# use path to prepared sandbox from previous step
vim /path/to/prepared/sandbox/config.yaml
```

```yaml
# required changes:
qemu:
  # change this
  distribution: change_me
analysis:
  kunai:
    # be careful of pointing to the right architecture bin
    path: /path/to/kunai
    # this is not mandatory but kunai CLI arguments can be changed here
    args: []
```

### 4. test that your VM is working

```bash
# this will spawn an interactive shell in the VM
kunai-sandbox -c /path/to/prepared/sandbox/config.yaml -i
```

### 5. test that the sandbox is working

```bash
# we run a test for 5s and store analysis results in directory /path/to/analysis
kunai-sandbox -t 5 -c /path/to/prepared/sandbox/config.yaml --test -o /path/to/analysis

# inspect the results in output directory
ls -hail /path/to/analysis
```

### 6. run a sample in the sandbox

If you do not have a malware sample or if you don't want to run one just
for the purpose of testing, you can just retrieve a binary from the VM

```bash
# by default the analysis timeout is 60s
./kunai-sandbox -c /path/to/prepared/sandbox/config.yaml -o /path/to/analysis -- /path/to/sample --some=sample --args

# inspect the results in output directory
ls -hail /path/to/analysis
```

You have everything ready to run your first malware sample in the sandbox

# Funding

The NGSOTI project is dedicated to training the next generation of Security Operation Center (SOC) operators, focusing on the human aspect of cybersecurity. It underscores the significance of providing SOC operators with the necessary skills and open-source tools to address challenges such as detection engineering, incident response, and threat intelligence analysis. Involving key partners such as CIRCL, Restena, Tenzir, and the University of Luxembourg, the project aims to establish a real operational infrastructure for practical training. This initiative integrates academic curricula with industry insights, offering hands-on experience in cyber ranges.

NGSOTI is co-funded under Digital Europe Programme (DEP) via the ECCC (European cybersecurity competence network and competence centre).



