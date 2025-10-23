#!/usr/bin/env bash

set -Eeuo pipefail

# end-host addresses
eh0_address="10.248.1.1"
eh1_address="10.248.2.1"

# client and proxy addresses
client00_address="10.248.1.10"
client01_address="10.248.100.10"
proxy10_address="10.248.2.10"
proxy11_address="10.248.100.11"

# mac addresses of interfaces
eh0mac="00:76:65:74:68:13"
client00mac="00:76:65:74:68:12"
client01mac="00:76:65:74:68:11"
eh1mac="00:76:65:74:68:23"
proxy10mac="00:76:65:74:68:22"
proxy11mac="00:76:65:74:68:21"

# namespaces representing the different machines
client_ns="client_ns"
eh0ns="eh0ns"
eh1ns="eh1ns"
proxy_ns="proxy_ns"

# interface names
eh0="eh0"
client00="client00"
client01="client01"
eh1="eh1"
proxy10="proxy10"
proxy11="proxy11"