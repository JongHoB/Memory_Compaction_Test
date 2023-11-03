#!/bin/bash

start_compaction(){
	echo "Manual compaction..."
	echo 1 > /proc/sys/vm/compact_memory
}

# Function to start tracing
start_tracing() {
	echo "Starting tracing..."
	echo 1 > /sys/kernel/debug/tracing/tracing_on
}

# Function to stop tracing
stop_tracing() {
	echo "Stopping tracing..."
	echo 0 > /sys/kernel/debug/tracing/tracing_on

}

# Function to print trace data
print_trace_data() {
	echo "Trace Data:"
	cat /sys/kernel/debug/tracing/trace > ./trace_manual_result.txt
	echo > /sys/kernel/debug/tracing/trace
}

start_tracing

start_compaction

sleep 15

stop_tracing

print_trace_data
