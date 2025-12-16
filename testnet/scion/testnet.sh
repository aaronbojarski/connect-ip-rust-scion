#!/usr/bin/env bash

set -Eeuo pipefail

# end-host addresses
eh0_address="10.248.1.1"
eh1_address="10.248.2.1"

# client and proxy addresses
client00_address="10.248.1.10"
proxy10_address="10.248.2.10"

# pocketscion addresses
pocketscion_client_address="10.248.100.20"
pocketscion_proxy_address="10.248.101.21"

# mac addresses of interfaces
eh0mac="00:76:65:74:68:13"
client00mac="00:76:65:74:68:12"
eh1mac="00:76:65:74:68:23"
proxy10mac="00:76:65:74:68:22"
pocketscion_client_mac="00:76:65:74:68:30"
pocketscion_proxy_mac="00:76:65:74:68:31"
client02mac="00:76:65:74:68:14"
proxy12mac="00:76:65:74:68:24"

# namespaces representing the different machines
client_ns="client_ns"
eh0ns="eh0ns"
eh1ns="eh1ns"
proxy_ns="proxy_ns"
pocketscion_ns="pocketscion_ns"

# interface names
eh0="eh0"
client00="client00"
client02="client02"
eh1="eh1"
proxy10="proxy10"
proxy12="proxy12"
ps_client="ps_client"
ps_proxy="ps_proxy"


# setup test network for one side
function net_up() {
	sudo ip netns add $nodexns
	sudo ip netns add $ehxns

	sudo ip link add $ehx address $ehxmac type veth peer name $nodex0 address $nodex0mac

	sudo ip link set dev $ehx netns $ehxns
	sudo ip link set dev $nodex0 netns $nodexns

	sudo ip -n $ehxns address add $ehx_address/28 dev $ehx

    sudo ip -n $nodexns address add $nodex0_address/28 dev $nodex0

	sudo ip -n $ehxns link set dev $ehx up
	sudo ip -n $ehxns link set dev lo up

	sudo ip -n $nodexns link set dev $nodex0 up

	sudo ip -n $nodexns link set dev lo up

	sudo ip -n $ehxns link set dev $ehx mtu 1500

	sudo ip -n $ehxns route add default via $nodex0_address
}

function testnet_up() {
	# create pocketscion namespace
	sudo ip netns add $pocketscion_ns

	# network on side 0
	ehx_address=$eh0_address
	ehy_address=$eh1_address
	nodex0_address=$client00_address
	nodexns=$client_ns
	ehxns=$eh0ns
	ehx=$eh0
	nodex0=$client00
	ehxmac=$eh0mac
	ehymac=$eh1mac
	nodex0mac=$client00mac

	net_up

	# network on side 1
	ehx_address=$eh1_address
	ehy_address=$eh0_address
	nodex0_address=$proxy10_address
	nodexns=$proxy_ns
	ehxns=$eh1ns
	ehx=$eh1
	nodex0=$proxy10
	ehxmac=$eh1mac
	ehymac=$eh0mac
	nodex0mac=$proxy10mac

	net_up

	# create veth pairs between client and pocketscion
	sudo ip link add $client02 address $client02mac type veth peer name $ps_client address $pocketscion_client_mac
	sudo ip link set dev $client02 netns $client_ns
	sudo ip link set dev $ps_client netns $pocketscion_ns

	# create veth pairs between proxy and pocketscion
	sudo ip link add $proxy12 address $proxy12mac type veth peer name $ps_proxy address $pocketscion_proxy_mac
	sudo ip link set dev $proxy12 netns $proxy_ns
	sudo ip link set dev $ps_proxy netns $pocketscion_ns

	# configure pocketscion namespace interfaces
	sudo ip -n $client_ns address add 10.248.100.10/24 dev $client02
	sudo ip -n $proxy_ns address add 10.248.101.11/24 dev $proxy12
	sudo ip -n $pocketscion_ns address add $pocketscion_client_address/24 dev $ps_client
	sudo ip -n $pocketscion_ns address add $pocketscion_proxy_address/24 dev $ps_proxy

	# bring up pocketscion interfaces
	sudo ip -n $client_ns link set dev $client02 up
	sudo ip -n $proxy_ns link set dev $proxy12 up
	sudo ip -n $pocketscion_ns link set dev $ps_client up
	sudo ip -n $pocketscion_ns link set dev $ps_proxy up
	sudo ip -n $pocketscion_ns link set dev lo up
}

function net_down() {
	sudo ip netns del $client_ns 2>/dev/null || true
	sudo ip netns del $proxy_ns 2>/dev/null || true
	sudo ip netns del $eh0ns 2>/dev/null || true
	sudo ip netns del $eh1ns 2>/dev/null || true
	sudo ip netns del $pocketscion_ns 2>/dev/null || true
}

function testnet_down() {
	net_down
}

function cleanup() {
	set +eu pipefail

	echo "perform cleanup"

	sudo ip netns del $client_ns 2>/dev/null || true
	sudo ip netns del $proxy_ns 2>/dev/null || true
	sudo ip netns del $eh0ns 2>/dev/null || true
	sudo ip netns del $eh1ns 2>/dev/null || true
	sudo ip netns del $pocketscion_ns 2>/dev/null || true

	sudo ip link delete $eh0 2>/dev/null || true
	sudo ip link delete $eh1 2>/dev/null || true
	sudo ip link delete $client02 2>/dev/null || true
	sudo ip link delete $proxy12 2>/dev/null || true
	sudo ip link delete $ps_client 2>/dev/null || true
	sudo ip link delete $ps_proxy 2>/dev/null || true
}

trap 'catch $? $LINENO' EXIT
catch() {
  if [ "$1" != "0" ]; then
		echo "Something Failed!"
    echo "Error $1 occurred on $2"
		cleanup
		exit 1
  fi
}


function usage() {
	echo "Usage:"
	echo "$0 up|down"
}

if [ $# -eq 0 ]
then
	echo "No argument provided."
	usage
	exit 1
fi

up_down=$1
if [ "$up_down" = "up" ];
then
	testnet_up
elif [ "$up_down" = "down" ];
then
	testnet_down
else
	echo "First argument must either be up or down"
	usage
	exit 1
fi

exit 0