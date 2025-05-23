#!/bin/bash

set -euxo pipefail

mkdir -p images


function debian_dl {
    DEBIAN_DIR=images/debian
    URL="$1"
    IMAGE=$(basename $URL)
    BASE_URL=$(dirname $URL)
    OUT="$DEBIAN_DIR/$IMAGE"

    mkdir -p $DEBIAN_DIR

    if [[ ! -f $OUT ]]
    then 
        curl -L $BASE_URL/SHA512SUMS | grep $IMAGE >> $DEBIAN_DIR/SHA512SUMS
        curl -L --output $OUT $URL 
        bash -c "cd $DEBIAN_DIR && sha512sum -c SHA512SUMS"
    fi
}

function ubuntu_dl {
    URL="$1"
    IMAGE=$(basename $URL)
    BASE_URL=$(dirname $URL)
    OUT_DIR="images/ubuntu"
    OUT="$OUT_DIR/$IMAGE"
    SHASUMS=SHA256SUMS

    mkdir -p $OUT_DIR

    if [[ ! -f $OUT ]]
    then 
        curl -L $BASE_URL/$SHASUMS | grep $IMAGE >> $OUT_DIR/$SHASUMS
        curl -L --output $OUT $URL 
        bash -c "cd $OUT_DIR && sha256sum -c $SHASUMS"
    fi
}

# put here downloads known to create working sandbox images
## debian
### bullseye
debian_dl https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2
debian_dl https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-arm64.qcow2

### bookworm
debian_dl https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
debian_dl https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.qcow2

## ubuntu
### ubuntu 20.04 LTS focal (kernel 5.4)
ubuntu_dl https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img
ubuntu_dl https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-arm64.img
### Ubuntu Server 22.04 LTS (Jammy Jellyfish) 
ubuntu_dl https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
ubuntu_dl https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img
### oracular images
ubuntu_dl https://cloud-images.ubuntu.com/oracular/current/oracular-server-cloudimg-amd64.img
ubuntu_dl https://cloud-images.ubuntu.com/oracular/current/oracular-server-cloudimg-arm64.img
### noble images
ubuntu_dl https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
ubuntu_dl https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img
