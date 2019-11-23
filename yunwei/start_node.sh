#!/bin/bash

install_ko(){
	install ./kernel/tcp_nanqinlang.ko /lib/modules/`uname -r`/kernel/net/ipv4
    insmod /lib/modules/`uname -r`/kernel/net/ipv4/tcp_nanqinlang.ko
    depmod -a
}

init_sys() {
    sed  -i '/net\.core\.default_qdisc/d' /etc/sysctl.conf
	sed  -i '/net\.ipv4\.tcp_congestion_control/d' /etc/sysctl.conf
	echo -e "\nnet.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo -e "net.ipv4.tcp_congestion_control=nanqinlang\c" >> /etc/sysctl.conf
	sysctl -p
}

check_status(){
	if [[ "`lsmod | grep nanqinlang`" != "" ]]; then
		echo -e "${Info} tcp_nanqinlang is installed !"
			if [[ "`sysctl net.ipv4.tcp_available_congestion_control | awk '{print $3}'`" = "nanqinlang" ]]; then
				 echo -e "${Info} tcp_nanqinlang is running !"
			else echo -e "${Error} tcp_nanqinlang is installed but not running !"
			fi
	else
		echo -e "${Error} tcp_nanqinlang not installed !"
	fi
}

replace_ip() {
    ip=`/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"`
    sed -i 's/replace_local_ip/'$ip'/g' ./node/conf/lego/conf
}

start(){
    install_ko
    init_sys
    replace_ip
    check_status
    cd ./node && nohup ./vpn_svr -f 0 -g 0 &
}

start