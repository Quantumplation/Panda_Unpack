echo "Running replay with unpack on $1"
~/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -replay logs/rr/$1 -m 1G -panda 'osi;unpack' -os windows-32-7

echo "Extracting VAD blocks for PID $2"
mkdir -p vads
volatility vaddump -f ./dump.raw --profile=Win7SP0x86 -D vads -p $2
