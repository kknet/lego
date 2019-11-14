rm -rf ./cbuild/vpn_svr*
strip ./cbuild/vpn_proxy -o ./cbuild/vpn_svr
cd ./cbuild
tar -zcvf ./vpn_svr.tar.gz ./vpn_svr
echo "scp now..."
sshpass -p Xf4aGbTaf9 scp ./vpn_svr.tar.gz root@167.71.232.145:/root/vpn_proxy
echo "succ."
