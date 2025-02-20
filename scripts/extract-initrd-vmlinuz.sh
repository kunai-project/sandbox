IMAGE="$(realpath $1)"
OUT_DIR="$(dirname $IMAGE)"
NBD=

set -euxo pipefail

if [[ ! -f $IMAGE ]]
then
    echo "Usage: $0 [VM_DISK_IMAGE]"
    exit 1
fi

RAW=${IMAGE}.raw

qemu-img convert -O raw $IMAGE $RAW

function extract_files()
{
    container="$1"
    while read file
    do  
        # if this is not a symbolic link
        if 7z l -slt $container $file | grep 'Symbolic Link = $'; then
            7z e -aoa -o./ $container $file
        fi
    done < <(7z l -slt $container | grep '^Path = ' | cut -d '=' -f 2 | sed 's/^ //' | grep -E '(^(boot/)?)(vmlinuz|initrd|initramfs).*?')
}

extract_files $RAW

for i in {0..10}
do
    if 7z e -aoa -o./ $RAW $i.img > /dev/null; then
        if [ -f  $i.img ]; then
            echo "we extracted $i.img"
            extract_files "$i.img"
            rm $i.img
        else
            # no need to try extracting further
            break;
        fi
    fi
done

# we remove raw image we created
rm $RAW