#!/usr/bin/env bash
round=${3:-0}
if (( round == 0 ))
then
  echo "Starting at round 0, and cleaning up from last run"
  rm -rf dumps
  rm -rf vads
  rm -rf vad_temps
  rm story.txt
else
  echo "Resuming at round $round"
fi

# Exit if ctrl+c
trap 'exit 130' INT

# Necessary folders
mkdir -p dumps
mkdir -p vads

round=${3:-0}

while true; do

  echo "Starting round $round..." >> story.txt
  echo "Running replay with unpack on $1 for round $round"
  ~/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -replay logs/rr/$1 -m 1G -panda 'osi;unpack:round='"$round" -os windows-32-7
  # If no dump file was created, the replay has finished!
  if [ ! -f "./dumps/dump.raw.$round" ]
  then
    echo "Replay completed! No memory dump created!"
    echo "Replay completed!" >> story.txt
    break
  fi

  echo "Dump found, Extracting VAD blocks for PID $2 round $round"
  mkdir -p vad_temps
  python ~/volatility/vol.py vaddump -f ./dumps/dump.raw.$round --profile=Win7SP0x86 -D vad_temps -p $2

  echo "Checking VAD blocks:" >> story.txt

  cd ./vad_temps
  for f in *.dmp
  do
    echo "Checking $f"
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
      echo "    $f has changed!" >> ../story.txt
      echo "$f is different! Copying it to the vads database"
      cp "$f" "../vads/${f}.${round}"
    fi
  done
  cd ..
  rm -rf vad_temps/*
  ((round++)) # Bash incrementing...
done

rm -rf vad_temps
