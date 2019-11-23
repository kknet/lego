ips=(
134.209.178.180 \
134.209.184.49 \
167.71.113.28 \
167.71.170.154 \
167.71.172.135 \
167.71.224.241 \
167.71.232.145 \
167.71.232.29
)

for ip in ${ips[@]}; do
        sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" root@$ip "$1" &
        echo $ip $1 " OK"
done
