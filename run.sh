#!/usr/bin/env bash
round=${4:-0}
if (( round == 0 ))
then
  echo "Starting at round 0, and cleaning up from last run"
  rm -rf "./${2}/dumps"
  rm -rf "./${2}/vads"
  rm -rf "./${2}/vad_temps"
  rm "./${2}/story.txt"
else
  echo "Resuming at round $round"
fi

# Exit if ctrl+c
trap 'exit 130' INT

# Necessary folders
mkdir -p "./${2}/dumps"
mkdir -p "./${2}/vads"

while true; do

  echo "Starting round $round..." >> "./${2}/story.txt"
  echo "Running replay with unpack on $1 for round $round"
  ~/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -replay logs/rr/$1 -m 1G -panda 'osi;unpack:process='"$2"',round='"$round" -os windows-32-7

  echo "Extracting VAD blocks for PID $3 round $round"
  mkdir -p "./${2}/vad_temps"
  python ~/volatility/vol.py vaddump -f "./${2}/dumps/dump.raw.${round}" --profile=Win7SP0x86 -D "./${2}/vad_temps" -p $3

  echo "Checking VAD blocks:" >> "./${2}/story.txt"

  cd "./${2}/vad_temps"
  for f in *.dmp
  do
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
  cd ../..
  rm -rf "./${2}/vad_temps/*"
  ((round++)) # Bash incrementing...
  # If the story file contains "Replay Finished!", we can do one more round of extraction
  if grep "Replay finished!" "./${2}/story.txt"
  then
    echo "Replay completed!"
    break
  fi

done

rm -rf "./${2}/vad_temps"
