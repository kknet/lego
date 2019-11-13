#sshpass -p Ct123456 scp ./cbuild/vpn_proxy root@122.112.234.133:/root/vpn &
#sshpass -p Ct123456 scp ./cbuild/vpn_proxy root@119.3.15.76:/root/vpn &
#sshpass -p Ct123456 scp ./cbuild/vpn_proxy root@119.3.73.78:/root/vpn &
sshpass -p Ct123456 scp -o "StrictHostKeyChecking no" ./cbuild/lego root@122.112.234.133:/root/node &
sshpass -p Ct123456 scp -o "StrictHostKeyChecking no" ./cbuild/lego root@119.3.15.76:/root/node &
sshpass -p Ct123456 scp -o "StrictHostKeyChecking no" ./cbuild/lego root@119.3.73.78:/root/node &

#sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild/lego root@120.77.2.117:/root/node &
#sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild/lego root@47.105.87.61:/root/node &
#sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild/lego root@121.199.11.177:/root/node &
