# Memory_Compaction_Test
Memory compaction function call tracing with ftrace and KGDB

---
- For Memory Stress, Using `stress-ng`
- https://github.com/ColinIanKing/stress-ng
- `sudo apt install stress-ng`
---
## Procedure with ftrace
- Need to check `ftrace` feature availability first
- Using `function_graph` for tracer
---

### 1. `trace_memory_stress.sh`
```
cd /sys/kernel/debug/tracing
cat available_tracers
echo function_graph > current_tracer
ps -ef | grep kcompactd
echo <PID> > /sys/kernel/debug/tracing/set_ftrace_pid
```
- Need to use **2 shells** for shutting down the stress test process before 10minutes.

<img width="500" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/0a92da69-f4d6-4ee3-aeb2-0e18bda069d8">


  ---

#### BUT SOMETHING IS ... SEEMS `KCOMPACTD` DOESN'T WORK PROPERLY
 <img width="387" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/7ae192ff-7779-4c3e-9b78-1682c8077bd0">
 
  - As we can see this image`(ftrace/trace_result.txt)`, there is no trace result.
  - `kcompactd` is invoked mainly by `kswapd` and we test the program with allocating 90% of memory capacity
  - so *probably* `kswapd` must be executed and also it would *probably* invoke the `kcompactd`
  - but there is no result.....Hmm


---
### 2.`trace_manual_compaction.sh`
- Need to make original state. `echo > set_ftrace_pid`
  
```
cat available_filter_functions
echo "*compact*" > set_ftrace_filter
echo "*migrate*" >> set_ftrace_filter

```  
- Execute the `shell script` and `stress-ng` **seperately**
- `stress-ng --vm 1 --vm-bytes 90% -t 10m` and `sh trace_manual_compaction.sh`
 ---
 #### Compare `OCI_ARM(3core, 18GB Ram)(VM instance)` and `X86_Server(24 Core, 128GB Ram)(Bare Metal)`
  - `ftrace/trace_manual_OCI_ARM_result.txt`
 <img width="482" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/2f82d03e-1e7e-4878-9b2a-5013e0a41789">
 
  - `ftrace/trace_manual_swarm_result.txt`
<img width="540" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/3573d62c-6edd-4183-987a-ed90824fc6e3">

   - In OCI, we can check that it tries to `migrate pages` for memory compaction.
   - But in X86 Server, we can see `compact_unlock_should_abort.isra.0()` but after this, we cannot see any *`migrate`* or kind of *`compact_zone`* symbol......
