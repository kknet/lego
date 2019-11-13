ps -ef | grep vpn_proxy | awk -F' ' '{print $2}' | xargs kill -9
rm -rf /root/vpn*/vpn_proxy
rm -rf /root/vpn*/core*
rm -rf /root/vpn*/log/*
cp ./cbuild/vpn_proxy /root/vpn1/
cp ./cbuild/vpn_proxy /root/vpn2/
cp ./cbuild/vpn_proxy /root/vpn3/
cp ./cbuild/vpn_proxy /root/vpn4/
cp ./cbuild/vpn_proxy /root/vpn5/
