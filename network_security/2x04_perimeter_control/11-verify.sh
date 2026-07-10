#!/bin/bash#!/bin/bash

wg show | grep -oP 'latest handshake: \K.*'