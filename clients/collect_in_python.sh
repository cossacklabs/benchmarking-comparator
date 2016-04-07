#/bin/bash

echo "">$1.res
python3.5 -W ignore $1 >>$1.res
echo -ne "$i\\r"
