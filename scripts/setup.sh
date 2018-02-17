#!/bin/bash

. ./var.txt

function compile {
        # build kernel module
        cd ${KERNEL_MODULE_PATH}

        make clean
        make

        # return to script directory
        cd -

        # build iproute package
        cd ${IPROUTE_PKG_PATH}
        ./configure
        make

        cd -
}

function setup_kernelmodule {
	cd ${KERNEL_MODULE_PATH}

	lsmod | grep ip6_tunnel
	if [ $? -eq 0 ]; then
		rmmod ip6_tunnel
	fi

	lsmod | grep tunnel6
	if [ $? -ne 0 ]; then
		modprobe tunnel6
	fi

	insmod ip6_tunnel.ko
}

function setup_ip6tunnel {
	${CUSTOM_IP_PATH} -6 tunnel add ${TUN_IF} mode skinny remote ${UNDERLAY_REMOTE_NET6} local ${UNDERLAY_LOCAL_NET6} dev ${NET_IF}
	ip link set dev ${TUN_IF} up
	ip -6 addr add ${OVERLAY_LOCAL_IP6} dev ${TUN_IF}
	ip -6 route add ${OVERLAY_REMOTE_NET6} dev ${TUN_IF}
}

if [ ${EUID:-${UID}} -ne 0 ]; then
	echo "Require root privilege"
	exit -1
fi

compile
setup_kernelmodule
setup_ip6tunnel
