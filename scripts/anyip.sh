#!/bin/bash

. ./var.txt

function setup_anyip {
	ip link set dev ${NET_IF} promisc on
	ip -6 route add local ${UNDERLAY_LOCAL_NET6} dev ${LOOPBACK_IF}
	ip -6 route add ${UNDERLAY_LOCAL_NET6} dev ${NET_IF}
	ip -6 route add ${UNDERLAY_REMOTE_NET6} dev ${NET_IF}
}


if [ ${EUID:-${UID}} -ne 0 ]; then
	echo "Require root privilege"
	exit -1
fi

setup_anyip
