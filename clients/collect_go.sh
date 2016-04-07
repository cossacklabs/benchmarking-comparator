#/bin/bash

echo "">$1.res
START=$(date +%s.%N)
#echo $START
for i in {1..10000};
do
    ./$1
    END=$(date +%s.%N)
    DIFF=$(echo "$END - $START" | bc)
    echo $i,$DIFF >>$1.res
    echo -ne "$i\\r"
done