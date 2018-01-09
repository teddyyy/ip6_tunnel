#!/bin/bash

# netns
NETNS_DEV_NAME="enp0s8"
NETNS_TUN_NAME="ip6tnl1"
NETNS_NAME="skinny-ns"

# network
UNDERLAY_NETWORK6="2001:2:0:1::/64"
UNDERLAY_LOCAL_IP6="2001:2:0:1::1/64"
UNDERLAY_REMOTE_IP6="2001:2:0:1::2/64"
OVERLAY_NETWORK6="2001:3:0:1::/64"
OVERLAY_LOCAL_IP6="2001:3:0:1::1/64"
OVERLAY_REMOTE_IP6="2001:3:0:1::2/64"

# path
KERNEL_MODULE_PATH="../kmod"
CUSTOM_IP_PATH="../iproute2-4.9.0/ip/ip"

function setup_netns {
	ip netns list | grep ${NETNS_NAME}
	if [ $? -eq 0 ]; then
		ip netns delete ${NETNS_NAME}
	fi

	ip netns add ${NETNS_NAME}
	ip link set ${NETNS_DEV_NAME} netns ${NETNS_NAME}
	ip netns exec ${NETNS_NAME} ip link set ${NETNS_DEV_NAME} up
	ip netns exec ${NETNS_NAME} ip -6 addr add ${UNDERLAY_LOCAL_IP6} dev ${NETNS_DEV_NAME}
	ip netns exec ${NETNS_NAME} ip -6 route add ${UNDERLAY_NETWORK6} dev ${NETNS_DEV_NAME}
}

function setup_kernelmodule {
	cd ${KERNEL_MODULE_PATH}

	make clean
	make

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
	ip netns exec ${NETNS_NAME} ${CUSTOM_IP_PATH} -6 tunnel add ${NETNS_TUN_NAME} mode skinny remote ${UNDERLAY_REMOTE_IP6} local ${UNDERLAY_LOCAL_IP6} dev ${NETNS_DEV_NAME}
	ip netns exec ${NETNS_NAME} ip link set dev ${NETNS_TUN_NAME} up
	ip netns exec ${NETNS_NAME} ip -6 addr add ${OVERLAY_LOCAL_IP6} dev ${NETNS_TUN_NAME}
	ip netns exec ${NETNS_NAME} ip -6 route add ${OVERLAY_NETWORK6} dev ${NETNS_TUN_NAME}
}

if [ ${EUID:-${UID}} -ne 0 ]; then
	echo "Require root privilege"
	exit -1
fi

echo "Setup IP6 over IP6 tunnel..."
setup_netns
setup_kernelmodule
setup_ip6tunnel
echo "Done!"
