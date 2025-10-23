#!/usr/bin/env bash

set -Eeuo pipefail

# include network variables
source "$(dirname "$0")/testnet_vars.sh"

# setup test network for one side
function net_up() {
	sudo ip netns add $nodexns
	sudo ip netns add $ehxns

	sudo ip link add $ehx address $ehxmac type veth peer name $nodex0 address $nodex0mac

	sudo ip link set dev $ehx netns $ehxns
	sudo ip link set dev $nodex0 netns $nodexns
	sudo ip link set dev $nodex1 netns $nodexns

	sudo ip -n $ehxns address add $ehx_address/24 dev $ehx

    sudo ip -n $nodexns address add $nodex0_address/24 dev $nodex0

	sudo ip -n $ehxns link set dev $ehx up
	sudo ip -n $ehxns link set dev lo up

	sudo ip -n $nodexns link set dev $nodex0 up
	sudo ip -n $nodexns link set dev $nodex1 up

	sudo ip -n $nodexns link set dev lo up

	sudo ip -n $ehxns link set dev $ehx mtu 1420

	sudo ip -n $ehxns route add default via $nodex0_address
}

function testnet_up() {
	# set up the two outer network interfaces, which are connected to each other.
	sudo ip link add $client01 address $client01mac type veth peer name $proxy11 address $proxy11mac

	# network on side 0
	ehx_address=$eh0_address
	ehy_address=$eh1_address
	nodex0_address=$client00_address
	nodexns=$client_ns
	ehxns=$eh0ns
	ehx=$eh0
	nodex0=$client00
	nodex1=$client01
	ehxmac=$eh0mac
	ehymac=$eh1mac
	nodex0mac=$client00mac
	nodex0mac=$client01mac
	nodey1mac=$proxy11mac

	net_up

	# network on side 1
	ehx_address=$eh1_address
	ehy_address=$eh0_address
	nodex0_address=$proxy10_address
	nodexns=$proxy_ns
	ehxns=$eh1ns
	ehx=$eh1
	nodex0=$proxy10
	nodex1=$proxy11
	ehxmac=$eh1mac
	ehymac=$eh0mac
	nodex0mac=$proxy10mac
	nodex0mac=$proxy11mac
	nodey1mac=$client01mac

	net_up

    sudo ip -n $client_ns address add $client01_address/24 dev $client01
    sudo ip -n $proxy_ns address add $proxy11_address/24 dev $proxy11

    # add route to the address given by the connect-ip server
    sudo ip -n eh1ns route add 10.248.3.0/24 via 10.248.2.10 dev eh1

    # add routes between the two node namespaces
    #sudo ip -n $client_ns route add $proxy11_address/32 dev $client01
    #sudo ip -n $proxy_ns route add $client01_address/32 dev $proxy11
}

function net_down() {
	sudo ip netns del $client_ns
	sudo ip netns del $proxy_ns
	sudo ip netns del $eh0ns
	sudo ip netns del $eh1ns
}

function testnet_down() {
	net_down
}

function cleanup() {
	set +eu pipefail

	echo "perform cleanup"

	sudo ip netns del $client_ns
	sudo ip netns del $proxy_ns
	sudo ip netns del $eh0ns
	sudo ip netns del $eh1ns

	sudo ip link delete $client01
	sudo ip link delete $proxy11
	sudo ip link delete $eh0
	sudo ip link delete $eh1
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