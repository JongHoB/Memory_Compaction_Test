# Memory_Compaction_Test
function call tracing with ftrace and memory stress in Kernel

---
- For Memory Stress, Using `stress-ng`
- https://github.com/ColinIanKing/stress-ng
- `sudo apt install stress-ng`
---
## Environment
- Need to check `ftrace` feature availability first
- I used `function_graph` for tracer
---

### 1. 1st Test with `trace_memory_stress.sh`
```
cd /sys/kernel/debug/tracing
cat available_tracers
echo function_graph > current_tracer
ps -ef | grep kcompactd
echo <PID> > /sys/kernel/debug/tracing/set_ftrace_pid
```
<img width="500" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/0a92da69-f4d6-4ee3-aeb2-0e18bda069d8">

- Need to use **2 shells** for shutting down the stress test process before 10minutes.

- BUT SOMETHING IS ... SEEMS `KCOMPACTD` DOESN'T WORK PROPERLY


### 2. 2nd Test with `trace_manual_compaction.sh`
- Execute the shell script and stress-ng seperately
- `stress-ng --vm 1 --vm-bytes 90% -t 10m` and `sh trace_manual_compaction.sh`
- Need to check further....
