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
        sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no"  $1 root@$ip:$2 &
        echo $ip $1 $2 " OK"
done
