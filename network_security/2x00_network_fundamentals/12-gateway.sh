#!/bin/bash
ip route show default | awk '{print $3}'