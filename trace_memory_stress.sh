#!/bin/bash

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
  cat /sys/kernel/debug/tracing/trace
}

# Function to handle Ctrl+C
handle_ctrl_c() {
  echo "stop"
  kill -9 $stress_ng_pid
  stop_tracing
  print_trace_data
  exit 1
}

# Set up Ctrl+C handler
trap handle_ctrl_c INT

# Start tracing
start_tracing

# Run stress-ng in the background
stress-ng --vm 1 --vm-bytes 90% -t 10m &

# Capture the process ID of the stress-ng command
stress_ng_pid=$(echo $!)

echo $stress_ng_pid

# Wait for the stress-ng command to finish
wait $stress_ng_pid

# Stop tracing
stop_tracing

# Print trace data
print_trace_data

