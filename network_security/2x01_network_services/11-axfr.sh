#!/bin/bash
dig "@$2" "$1" AXFR | grep -q "XFR size" && dig "@$2" "$1" AXFR || echo "; Transfer failed."