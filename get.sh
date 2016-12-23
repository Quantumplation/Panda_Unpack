mkdir -p archives/
wget -P archives/ http://giantpanda.gtisc.gatech.edu/malrec/rr/$1.txz
tar xJvf archives/$1.txz
python bpatch.py logs/rr/$1.patch
