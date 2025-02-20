#!/bin/bash 

# This scripts helps preparing a sandbox image with the help
# of cloud-init. So that it works, one needs to use cloud-init
# ready images from any distribution.
# 
# Warning: this script has been tested on a x86_64 host and is
# able to generate both x86_64 and arm64 based sandbox images.
# this script might need to be adapted if it is run from another
# architecture or if it needs to support another target architecture.

IMAGE="$1"
OUT="$2"

if [[ ! $OUT || ! $IMAGE ]]
then
    echo "Usage: $0 QCOW2_IMAGE OUT_DIR"
    exit 1
fi

set -euxo pipefail

mkdir -p $OUT

# cleanup stuff
rm -f $OUT/vmlinuz* $OUT/initr* $OUT/*.qcow2 $OUT/*.img

cp $IMAGE $OUT

IMAGE_FILE="$(basename $IMAGE)"
CURRENT_DIR=$(dirname $(realpath $0))

# paths to the tools we will need
EXTRACTOR=$CURRENT_DIR/extract-initrd-vmlinuz.sh

# so far only two archs are supported
ARCH=
if grep -P '(amd64|x86_64)' <<<$IMAGE_FILE
then
  ARCH="x86_64"
elif grep -P '(arm64|aarch64)' <<<$IMAGE_FILE
then
  ARCH="aarch64"
fi

if [ ! $ARCH ]
then
  echo "Error: target achitecture cannot be found"
  exit 1
fi

# switching to output directory
pushd $OUT

# we resize qcow2 image to have a decent size
qemu-img resize $IMAGE_FILE 60G

# we need to extract vmlinuz and initrd to be cross-architecture
$EXTRACTOR $IMAGE_FILE


# preparing SSH settings
rm -rf ssh
mkdir ssh
ssh-keygen -N "" -f ssh/sandbox

SSH_PUB_KEY=$(cat ssh/sandbox.pub | cut -d ' ' -f -2)
OS=$(cut -d '-' -f 1 <<<$IMAGE_FILE)

# if USERNAME is set takes it otherwise takes default "sandbox"
SBX_USER=${SBX_USER-sandbox}
# if PASSWORD is set takes it otherwise takes default "password"
PASSWORD=${PASSWORD-password}


# preparing cloud-init
## meta-data file
cat <<EOF > meta-data
instance-id: $OS-instance
local-hostname: kunai-sandbox
EOF

## user-data file
### NB it is possible to upgrade packages with 
### package_upgrade: true but this slows down the
### preparation process.

PACKAGE_UPGRADE=${PACKAGE_UPGRADE-false}

cat <<EOF > user-data
#cloud-config

package_update: true
package_upgrade: $PACKAGE_UPGRADE

packages:
  - strace
  - busybox-static

users:
  - name: $SBX_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin
    home: /home/$SBX_USER
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: '$PASSWORD'
    ssh_authorized_keys:
        - $SSH_PUB_KEY
ssh_pwauth: True
chpasswd:
  list: |
    $SBX_USER:$PASSWORD
  expire: False

runcmd:
    - echo "installation completed"

EOF

# generate cloud-init iso
genisoimage -output init.iso -volid cidata -joliet -rock user-data meta-data

# for arm kernel we have to specify the kernel to boot
# we get an error when restoring snapshot if we don't keep init.iso
# in command

# kernel command line parameters
CMDLINE_LINUX=${CMDLINE_LINUX-}
CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf ${CMDLINE_LINUX}"

QEMU_ARGS=${QEMU_ARGS-}

if [[ $ARCH == "aarch64" ]]
then
  CPU=${CPU-cortex-a57}
  BASE_CMD="qemu-system-$ARCH -M virt -cpu $CPU -m 4G -smp 4 -kernel $(basename ./vmlinuz*) -initrd $(basename ./initr*) -append \"root=/dev/vda1 $CMDLINE_LINUX\" -drive file=$(basename $IMAGE_FILE),if=virtio -device virtio-net-pci,netdev=net0 -cdrom init.iso -boot d -nographic $QEMU_ARGS"
elif [[ $ARCH == "x86_64" ]]
then
  BASE_CMD="qemu-system-$ARCH -m 4G -smp 4 -kernel $(basename ./vmlinuz*) -initrd $(basename ./initr*) -append \"root=/dev/vda1 console=ttyS0 $CMDLINE_LINUX\" -drive file=$(basename $IMAGE_FILE),if=virtio -device virtio-net-pci,netdev=net0 -cdrom init.iso -boot d -nographic -enable-kvm $QEMU_ARGS"
fi

echo $BASE_CMD -netdev user,id=net0 -monitor unix:qemu-monitor,server,nowait | bash > install.log &

# we wait for cloud-init target to be finished
while ! grep -qP "Cloud-init.*finished" install.log
do
    sleep 1
done

sleep 5

SNAPSHOT=clean
# save initial state and quit
echo "savevm $SNAPSHOT" | socat - ./qemu-monitor

# wait for snapshot to be ready
while ! echo "info snapshots" | socat - ./qemu-monitor | grep -qP "$SNAPSHOT"
do
  sleep 1
done

# show snapshots
echo "info snapshots" | socat - ./qemu-monitor
echo "quit" | socat - ./qemu-monitor

# get linux kernel info
VERSION_LINE=$(cat install.log | grep -i 'Linux version' | head -n 1)
KERNEL=$(echo $VERSION_LINE | grep -oP 'Linux version .*?\s' | awk '{print $NF}' | cut -d '-' -f -2)
DISTRIBUTION="change_me"

if grep -iP 'ubuntu' <<< $VERSION_LINE;then
  DISTRIBUTION="ubuntu"
elif grep -iP 'debian' <<< $VERSION_LINE;then
  DISTRIBUTION="debian"
fi

IDENTITY="./ssh/sandbox"
# calls ks-gen-config (assumes sandbox tools have been installed)
ks-gen-config -u $SBX_USER -i $IDENTITY -k $KERNEL -d $DISTRIBUTION -a $ARCH -s $SNAPSHOT -r ./ -- $(echo $BASE_CMD -netdev "user,id=net0,hostfwd=tcp::{{ssh-port-fw}}-:22" -object "filter-dump,id=dump,netdev=net0,file={{pcap-file}}") > config.yaml
