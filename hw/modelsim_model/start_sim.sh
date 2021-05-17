#!/usr/bin/env bash

set -e

if [ -z "$DISPLAY" ]; then
    readonly exec_flag="-c"
else
    readonly exec_flag="-c"
fi

vsim "$exec_flag" -do 'source run.tcl'

