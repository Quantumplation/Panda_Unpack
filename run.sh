echo "Cleaning last run"
rm -rf dumps
rm -rf vads
rm -rf vad_temps

# Exit if ctrl+c
trap 'exit 130' INT

# Necessary folders
mkdir -p dumps
mkdir -p vads

for round in {0..5}
do

  echo "Running replay with unpack on $1 for round $round"
  ~/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -replay logs/rr/$1 -m 1G -panda 'osi;unpack:round='"$round" -os windows-32-7

  echo "Extracting VAD blocks for PID $2 round $round"
  mkdir -p vad_temps
  volatility vaddump -f ./dumps/dump.raw.$round --profile=Win7SP0x86 -D vad_temps -p $2

  cd ./vad_temps
  for f in *.dmp; do
    copy=true
    glob="../vads/${f}.*"
    for prev_file in $glob
    do
      if cmp -s "$f" "$prev_file"
      then
        copy=false
        break
      fi
    done
    if $copy
    then
      echo "$f is different! Copying it to the vads database"
      cp "$f" "../vads/${f}.${round}"
    fi
  done
  cd ..
  rm -rf vad_temps/*
done

rm -rf vad_temps
