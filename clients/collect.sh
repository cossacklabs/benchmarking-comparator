#/bin/bash

for i in {1..100};
do
    python3.5 $1;
    echo -ne "$i\\r"
done