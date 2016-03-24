#/bin/bash

cat $1 | grep in | awk '{if ($2 != 0) {s+=$2; c+=1} } END {print "in: " s/(c/2)}'
cat $1 | grep out | awk '{if ($2 != "0") {s+=$2; c+=1} } END {print "out: " s/(c/2)}'
cat $1 | grep $1 | awk '{if ($2 != "0") {s+=$2; c+=1} } END {print "time: " s/(c/2)}'