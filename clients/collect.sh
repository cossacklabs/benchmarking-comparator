#/bin/bash

echo "">$1.res
START=$(date +%s.%N)
#echo $START
for i in {1..100000};
do
    python3.5 -W ignore $1 $i
    END=$(date +%s.%N)
    DIFF=$(echo "$END - $START" | bc)
    echo $i,$DIFF >>$1.res
    echo -ne "$i\\r"
done