#!/bin/bash
dig "@$1" +short "$2" A | head -1