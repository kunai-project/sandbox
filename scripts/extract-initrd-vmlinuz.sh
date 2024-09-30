IMAGE="$(realpath $1)"
NBD=

set -euxo pipefail

for i in {0..10}
do
    if ! sudo fuser /dev/nbd$i
    then
        NBD=/dev/nbd$i
        break;
    fi
done

if [[ ! -f $IMAGE ]]
then
    echo "Usage: $0 [VM_DISK_IMAGE]"
    exit 1
fi

# we connect a nbd
sudo qemu-nbd -r -c $NBD $IMAGE
sleep 1

while read line
do
    tmp=$(mktemp -d)
    dev=$(awk '{print $1}'<<<$line)
    offset=$(awk '{print $2}'<<<$line)

    # by default consider 512 size sectors
    if sudo mount -o ro,offset=$(($offset*512)) $NBD $tmp
    then
        boot=$tmp/boot
        if [[ -d $boot ]]
        then
            ls -hail $boot
            # we files needed to boot the vm
            while read file
            do
                # we store vmlinuz and initrd in the directory
                # where the image is located
                tmp_file=$(mktemp --suffix="-extracted")
                # some images require root to read file(s)
                sudo cp $file $tmp_file
                sudo chown $(id -u):$(id -g) $tmp_file
                cp $tmp_file $(dirname $IMAGE)/$(basename $file)
            done < <(find $boot -type f -name vmlinuz* -or -name initrd* -or -name initramfs*)
        fi
        # unmount partition
        sudo umount $tmp
    fi
    rmdir $tmp
done < <(sudo fdisk -l $NBD | awk '/^\/dev/{print $1, $2}')

# we disconnect our nbd
sudo qemu-nbd -d $NBD

