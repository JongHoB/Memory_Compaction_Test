# Memory_Compaction_Test

Memory compaction function call tracing with ftrace and KGDB

---

- Concept of Memory Compaction
    
    [Memory Compaction in Linux Kernel.pdf](https://www.slideshare.net/AdrianHuang/memory-compaction-in-linux-kernelpdf)
    

---

- For Memory Stress, Using `stress-ng`
- https://github.com/ColinIanKing/stress-ng
- `sudo apt install stress-ng`

---

## Procedure with ftrace

- Need to check `ftrace` feature availability first
- Using `function_graph` for tracer
- `TEST` History
    
    ### 1. `trace_memory_stress.sh`
    
    - <details><summary>`trace_memory_stress.sh`</summary>
      
        - In the `trace_memory_stress.sh`, it will trace the `kcompactd` during `stress-ng --vm 3 --vm-bytes 90% -t 10m &`
        - You need to set the environment as follows first.
        
        ```bash
        cd /sys/kernel/debug/tracing
        cat available_tracers
        echo function_graph > current_tracer
        ps -ef | grep kcompactd
        echo <PID> > /sys/kernel/debug/tracing/set_ftrace_pid
        ```
        
        - Need to use **2 shells** for shutting down the stress test process before 10minutes if you want or Change the minutes for execution.
        
        <img width="500" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/0a92da69-f4d6-4ee3-aeb2-0e18bda069d8">
        
        ---
        
        ### BUT SOMETHING IS ... SEEMS `KCOMPACTD` DOESN'T WORK PROPERLY
        
        <img width="387" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/7ae192ff-7779-4c3e-9b78-1682c8077bd0">
        
        - As we can see this image`(ftrace/trace_result.txt)`, there is no trace result.
        - `kcompactd` is invoked mainly by `kswapd` and we test the program with allocating 90% of memory capacity
        - so *probably* `kswapd` must be executed and also it would  invoke the `kcompactd`
        - but there is no result.....Hmm
        - (this kernel version was 5.4.0 so the proactive compaction would not be executed.)
    </details>
    
    ---
    
    ### 2.`trace_manual_compaction.sh`
    
    - <details><summary>`trace_manual_compaction.sh`</summary>
      
        - *If you did `trace_memory_stress.sh` test, Need to make original state. `echo > set_ftrace_pid`*
        
        ---
        
        ```bash
        cat available_filter_functions
        echo "*compact*" > set_ftrace_filter
        echo "*migrate*" >> set_ftrace_filter
        ```
        
        - Execute the `shell script` and `stress-ng` **seperately**
        - `stress-ng --vm 1 --vm-bytes 90% -t 10m` and `sh trace_manual_compaction.sh`
        
        ---
        
        ### Compare `OCI_ARM(3core, 18GB Ram)(VM instance)` and `X86_Server(24 Core, 128GB Ram)(Bare Metal)`
        
        - `ftrace/trace_manual_OCI_ARM_result.txt`
        <img width="482" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/2f82d03e-1e7e-4878-9b2a-5013e0a41789">
        
        - `ftrace/trace_manual_swarm_result.txt`
        <img width="540" alt="image" src="https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/3573d62c-6edd-4183-987a-ed90824fc6e3">
        
        - In OCI, we can check that it tries to `migrate pages` for memory compaction.
        - But in X86 Server, we can see `compact_unlock_should_abort.isra.0()` but after this, we cannot see any *`migrate`* or kind of *`compact_zone`* symbol......
        - [See the reasons in KGDB below. In `compact_unlock_should_abort` in **ftrace test** chapter](#compact_unlock_should_abort-in-ftrace-test)
      </details>

      
---

## Linux VM for KGDB - Use linux-6.6.0

- Comparing to 5.4.0(previous installed version in x86 server), lots of features are added.
- `proactive compaction, memory folios, ....`

---

- **1. LAUNCH VM**
      <details><summary>launch vm</summary>
      
    ```bash
    sudo apt-get install -y pkg-config  libglib2.0-dev  libpixman-1-dev libslirp-dev
    
    ```
    
    ```bash
    # DOWNLOAD QEMU
    wget <https://download.qemu.org/qemu-8.1.2.tar.xz>
    tar xvJf qemu-8.1.2.tar.xz
    cd qemu-8.1.2
    ./configure --enable-slirp
    make
    
    ```
    
    ```bash
    # DOWNLOAD LINUX
    wget <https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz>
    tar -xvf linux-6.6.tar.xz
    #copy the config file
    cp linux-6.60.config linux-6.6/.config
    cd linux-6.6
    
    ```
    
    ```bash
    
    make menuconfig # Load the config and Save and EXIT
    make -j$(nproc) # BUILD
    
    ```
    
    ```bash
    #CREATE IMAGE with bootstrap 
    cd ..
    chmod +x create_image.sh
    ./create_image.sh
    ```
    
    ```elixir
    ./launch-vm.sh
    ```
    
    - Actually, i tried to access the vm with `ssh` but there seems error with *network configuration.* But i will pass this step (will **FIX IT**) ( **THIS THING IS NOT THE PRIORITIZED** for testing the compaction)
    - YOU CAN **TURN OFF THE QEMU** USING `Ctrl+a and x`
  
</details>
 
- **2. LAUNCH VM AND KGDB TOGETHER**

  <details><summary>LAUNCH VM AND KGDB TOGETHER</summary>

    ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/f599dcae-1368-47c6-88bf-5e28a80f9d56)

    - It would be better to use **TMUX**
    - You need at least 2 screen for **KGDB in Host(Original)** and for **QEMU**
    - I just add one more screen to see the **kernel source**
    - Procedure
        1. launch vm
        2. In host, `gdb linux-6.6/vmlinux` 
            1. and `target remote [localhost:4321](http://localhost:4321)` 
        3. you can use gdb commands. 

  </details>
  
- `compact_unlock_should_abort` in **ftrace test**

   <details><summary>compact_unlock_should_abort</summary>
    
    - I debug `compact_unlock_should_abort` function. ⇒ **It was in ftrace test history above**
    
    ```c
    /*
     * Compaction requires the taking of some coarse locks that are potentially
     * very heavily contended. The lock should be periodically unlocked to avoid
     * having disabled IRQs for a long time, even when there is nobody waiting on
     * the lock. It might also be that allowing the IRQs will result in
     * need_resched() becoming true. If scheduling is needed, compaction schedules.
     * Either compaction type will also abort if a fatal signal is pending.
     * In either case if the lock was locked, it is dropped and not regained.
     *
     * Returns true if compaction should abort due to fatal signal pending.
     * Returns false when compaction can continue.
     */
    static bool compact_unlock_should_abort(spinlock_t *lock,
    		unsigned long flags, bool *locked, struct compact_control *cc)
    {
    	if (*locked) {
    		spin_unlock_irqrestore(lock, flags);
    		*locked = false;
    	}
    
    	if (fatal_signal_pending(current)) {
    		cc->contended = true;
    		return true;
    	}
    
    	cond_resched();
    
    	return false;
    }
    
    -FATAL SIGNAL Pending - Check if there is a pending signal in current process
    SIGKILL,...........
    ```
    
    - FATAL SIGNAL Pending - Check if there is a pending signal in current process
    (SIGKILL,SIGTRAP…..)
    
    ```c
    static inline int task_sigpending(struct task_struct *p)
    {
    	return unlikely(test_tsk_thread_flag(p,TIF_SIGPENDING));
    }
    static inline int __fatal_signal_pending(struct task_struct *p)
    {
    	return unlikely(sigismember(&p->pending.signal, SIGKILL));
    }
    
    static inline int fatal_signal_pending(struct task_struct *p)
    {
    	return task_sigpending(p) && __fatal_signal_pending(p);
    }
    ```
    
    ---
    
    ```c
    #0  compact_unlock_should_abort (cc=<optimized out>, locked=<optimized out>, flags=<optimized out>,
        lock=<optimized out>) at mm/compaction.c:569
    #1  isolate_freepages_block (cc=cc@entry=0xffffc9000067fd00, start_pfn=start_pfn@entry=0xffffc9000067f958,
        end_pfn=end_pfn@entry=4456448, freelist=freelist@entry=0xffffc9000067fd00, stride=stride@entry=1,
        strict=strict@entry=false) at mm/compaction.c:614
    #2  0xffffffff81325831 in isolate_freepages (cc=0xffffc9000067fd00) at mm/compaction.c:1711
    #3  compaction_alloc (src=src@entry=0xffffea0004075e40, data=data@entry=18446683600576838912) at mm/compaction.c:1769
    #4  0xffffffff813a2c0a in migrate_folio_unmap (ret=0xffffc9000067fad0, reason=MR_COMPACTION, mode=MIGRATE_ASYNC,
        dstp=<synthetic pointer>, src=0xffffea0004075e40, private=18446683600576838912,
        put_new_folio=0xffffffff81322ec0 <compaction_free>, get_new_folio=0xffffffff81325120 <compaction_alloc>)
        at mm/migrate.c:1123
    #5  migrate_pages_batch (from=from@entry=0xffffc9000067fbb0,
        get_new_folio=get_new_folio@entry=0xffffffff81325120 <compaction_alloc>,
        put_new_folio=put_new_folio@entry=0xffffffff81322ec0 <compaction_free>,
        private=private@entry=18446683600576838912, mode=mode@entry=MIGRATE_ASYNC, reason=reason@entry=0,
        ret_folios=0xffffc9000067fad0, split_folios=0xffffc9000067fbd0, stats=0xffffc9000067fae4, nr_pass=3)
        at mm/migrate.c:1660
    #6  0xffffffff813a3582 in migrate_pages_sync (from=from@entry=0xffffc9000067fbb0,
        get_new_folio=get_new_folio@entry=0xffffffff81325120 <compaction_alloc>,
        put_new_folio=put_new_folio@entry=0xffffffff81322ec0 <compaction_free>,
        private=private@entry=18446683600576838912, mode=mode@entry=MIGRATE_SYNC, reason=reason@entry=0,
        ret_folios=0xffffc9000067fbc0, split_folios=0xffffc9000067fbd0, stats=0xffffc9000067fbe4) at mm/migrate.c:1825
    #7  0xffffffff813a4125 in migrate_pages (from=from@entry=0xffffc9000067fd10,
        get_new_folio=get_new_folio@entry=0xffffffff81325120 <compaction_alloc>,
        put_new_folio=put_new_folio@entry=0xffffffff81322ec0 <compaction_free>,
        private=private@entry=18446683600576838912, mode=MIGRATE_SYNC, reason=reason@entry=0,
        ret_succeeded=0xffffc9000067fcbc) at mm/migrate.c:1929
    #8  0xffffffff81327b7a in compact_zone (cc=cc@entry=0xffffc9000067fd00, capc=capc@entry=0x0 <fixed_percpu_data>)
        at mm/compaction.c:2515
    #9  0xffffffff81328536 in compact_node (nid=nid@entry=0) at mm/compaction.c:2812
    #10 0xffffffff81328662 in compact_nodes () at mm/compaction.c:2825
    #11 sysctl_compaction_handler (table=<optimized out>, buffer=<optimized out>, length=<optimized out>,
        ppos=<optimized out>, write=<optimized out>) at mm/compaction.c:2871
    #12 sysctl_compaction_handler (table=<optimized out>, write=<optimized out>, buffer=<optimized out>,
        length=<optimized out>, ppos=<optimized out>) at mm/compaction.c:2858
    #13 0xffffffff814a6bb7 in proc_sys_call_handler (iocb=<optimized out>, iter=0xffffc9000067fe58, write=write@entry=1)
        at fs/proc/proc_sysctl.c:600
    #14 0xffffffff814a6cb3 in proc_sys_write (iocb=<optimized out>, iter=<optimized out>) at fs/proc/proc_sysctl.c:626
    #15 0xffffffff813ef341 in call_write_iter (file=0xffff8881026d3200, iter=0xffffc9000067fe58, kio=0xffffc9000067fe80)
        at ./include/linux/fs.h:1956
    #16 new_sync_write (ppos=0xffffc9000067fef0, len=2, buf=0x55555574aeb0 "1\n", filp=0xffff8881026d3200)
        at fs/read_write.c:491
    #17 vfs_write (pos=0xffffc9000067fef0, count=2, buf=0x55555574aeb0 "1\n", file=0xffff8881026d3200)
        at fs/read_write.c:584
    #18 vfs_write (file=0xffff8881026d3200, buf=0x55555574aeb0 "1\n", count=<optimized out>, pos=0xffffc9000067fef0)
        at fs/read_write.c:564
    #19 0xffffffff813ef657 in ksys_write (fd=<optimized out>, buf=0x55555574aeb0 "1\n", count=2) at fs/read_write.c:637
    #20 0xffffffff813ef70a in __do_sys_write (count=<optimized out>, buf=<optimized out>, fd=<optimized out>)
        at fs/read_write.c:649
    #21 __se_sys_write (count=<optimized out>, buf=<optimized out>, fd=<optimized out>) at fs/read_write.c:646
    #22 __x64_sys_write (regs=<optimized out>) at fs/read_write.c:646
    #23 0xffffffff81e5193b in do_syscall_x64 (nr=<optimized out>, regs=0xffffc9000067ff58) at arch/x86/entry/common.c:50
    #24 do_syscall_64 (regs=0xffffc9000067ff58, nr=<optimized out>) at arch/x86/entry/common.c:80
    #25 0xffffffff820000d2 in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:120
    ```
    
    ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/4c87a683-c454-4f8b-bf38-85c6d2e2cf6b)
    
    - **`compact_unlock_should_abort` is called by `isolate_freepages_block`**
    - When we see the image and the call stack, kind of `migrate_pages` or `compact*` symbols should be detected.
        - I see the log again (**`trace_manual_swarm_result.txt`)**
            
            ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/424648ca-a578-4e53-8a36-99cdbb5daf84)
            
            - …..I can see some trace results at the tail.
            - **So the compaction command was executed properly with high probability.**

    </details>
    
- `kcompactd` function

  <details><summary>kcompactd</summary>
    
    ```c
    #kcompactd function in Linux 6.6
    #mm/compaction.c
    /*
     * The background compaction daemon, started as a kernel thread
     * from the init process.
     */
    static int kcompactd(void *p)
    {
    	pg_data_t *pgdat = (pg_data_t *)p;
    	struct task_struct *tsk = current;
    	long default_timeout = msecs_to_jiffies(HPAGE_FRAG_CHECK_INTERVAL_MSEC);
    	long timeout = default_timeout;
    
    	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);
    
    	if (!cpumask_empty(cpumask))
    		set_cpus_allowed_ptr(tsk, cpumask);
    
    	set_freezable();
    
    	pgdat->kcompactd_max_order = 0;
    	pgdat->kcompactd_highest_zoneidx = pgdat->nr_zones - 1;
    
    	while (!kthread_should_stop()) {
    		unsigned long pflags;
    
    		/*
    		 * Avoid the unnecessary wakeup for proactive compaction
    		 * when it is disabled.
    		 */
    		if (!sysctl_compaction_proactiveness)
    			timeout = MAX_SCHEDULE_TIMEOUT;
    		trace_mm_compaction_kcompactd_sleep(pgdat->node_id);
    		if (wait_event_freezable_timeout(pgdat->kcompactd_wait,
    			kcompactd_work_requested(pgdat), timeout) &&
    			!pgdat->proactive_compact_trigger) {
    
    			psi_memstall_enter(&pflags);
    			kcompactd_do_work(pgdat);
    			psi_memstall_leave(&pflags);
    			/*
    			 * Reset the timeout value. The defer timeout from
    			 * proactive compaction is lost here but that is fine
    			 * as the condition of the zone changing substantionally
    			 * then carrying on with the previous defer interval is
    			 * not useful.
    			 */
    			timeout = default_timeout;
    			continue;
    		}
    
    		/*
    		 * Start the proactive work with default timeout. Based
    		 * on the fragmentation score, this timeout is updated.
    		 */
    		timeout = default_timeout;
    		if (should_proactive_compact_node(pgdat)) {
    			unsigned int prev_score, score;
    
    			prev_score = fragmentation_score_node(pgdat);
    			proactive_compact_node(pgdat);
    			score = fragmentation_score_node(pgdat);
    			/*
    			 * Defer proactive compaction if the fragmentation
    			 * score did not go down i.e. no progress made.
    			 */
    			if (unlikely(score >= prev_score))
    				timeout =
    				   default_timeout << COMPACT_MAX_DEFER_SHIFT;
    		}
    		if (unlikely(pgdat->proactive_compact_trigger))
    			pgdat->proactive_compact_trigger = false;
    	}
    
    	return 0;
    }
    ```
    
    - Because of `Proactive Compaction` , `kcompactd` **should be detected every *500ms*.**
        
        [Proactive Compaction](https://nitingupta.dev/post/proactive-compaction/)
        
    - I add break point in `trace_mm_compaction_kcompactd_sleep(pgdat->node_id);` line. Then it will break. **(It is important to choose appropriate line for break point because it could be not detected.)**
        
        ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/634b3e3b-afb7-45f0-96cc-e4822855f32c)
        
    
    ---
    
  </details>
    
- `stress-ng` : Maybe it needs to **be changed.**

  <details><summary>stress-ng</summary>
  
    - I add lots of **printk** to check the compaction.
    
    ```c
    /*
     * The background compaction daemon, started as a kernel thread
     * from the init process.
     */
    static int kcompactd(void *p)
    {
            pg_data_t *pgdat = (pg_data_t *)p;
            struct task_struct *tsk = current;
            long default_timeout = msecs_to_jiffies(HPAGE_FRAG_CHECK_INTERVAL_MSEC);
            long timeout = default_timeout;
    
            const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);
    
            if (!cpumask_empty(cpumask))
                    set_cpus_allowed_ptr(tsk, cpumask);
    
            set_freezable();
    
            printk("1\n");
    
            pgdat->kcompactd_max_order = 0;
            pgdat->kcompactd_highest_zoneidx = pgdat->nr_zones - 1;
    
            while (!kthread_should_stop()) {
                    unsigned long pflags;
    
                    printk("2\n");
                    /*
                     * Avoid the unnecessary wakeup for proactive compaction
                     * when it is disabled.
                     */
    								if (!sysctl_compaction_proactiveness)
                            timeout = MAX_SCHEDULE_TIMEOUT;
                    printk("3\n");
                    trace_mm_compaction_kcompactd_sleep(pgdat->node_id);
                    if (wait_event_freezable_timeout(pgdat->kcompactd_wait,
                            kcompactd_work_requested(pgdat), timeout) &&
                            !pgdat->proactive_compact_trigger) {
    
                            psi_memstall_enter(&pflags);
                            kcompactd_do_work(pgdat);
                            psi_memstall_leave(&pflags);
                            /*
                             * Reset the timeout value. The defer timeout from
                             * proactive compaction is lost here but that is fine
                             * as the condition of the zone changing substantionally
                             * then carrying on with the previous defer interval is
                             * not useful.
                             */
                            timeout = default_timeout;
                            printk("4\n");
                            continue;
                    }
    
                    /*
                     * Start the proactive work with default timeout. Based
                     * on the fragmentation score, this timeout is updated.
                     */
                    timeout = default_timeout;
                    if (should_proactive_compact_node(pgdat)) {
                            unsigned int prev_score, score;
                            printk("5\n");
    
                            prev_score = fragmentation_score_node(pgdat);
                            proactive_compact_node(pgdat);
                            score = fragmentation_score_node(pgdat);
                            /*
                             * Defer proactive compaction if the fragmentation
                             * score did not go down i.e. no progress made.
                             */
                            printk("6\n");
                            if (unlikely(score >= prev_score))
                                    timeout =
                                       default_timeout << COMPACT_MAX_DEFER_SHIFT;
                    }
                    printk("7\n");
                    if (unlikely(pgdat->proactive_compact_trigger))
                            pgdat->proactive_compact_trigger = false;
                    printk("8\n");
            }
            printk("9\n");
    
            return 0;
    }
    ```
    
    - `stress-ng --vm 8 --vm-bytes 90% -t 10m`
        - BUT IT ONLY prints **2,3,7,8,2,3,7,8,2,3,7,8…………**
        - ***Need to see `5,6` for proactive compaction***
        - I changed the vm or bytes several times.
    - ALSO `cat /proc/vmstat`
        - *There was nothing happened….*
            
            ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/f0bdc634-337e-4abc-b4b5-2a26b6b3e6c7)
            
        - Even if i did `stress-ng --vm 8 --vm-bytes 90% -t 10m` and `echo 1 > /proc/sys/vm/compact_memory` (manually compaction)
            
            ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/32ce8776-bcc3-4f58-95cd-8574a00e2a01)
            
        - **No success…..**
            
            ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/da46a20f-793a-4731-834a-5229c557cfb1)

    </details>


- `stress-ng` commands
    - Actually in [Memory Compaction in Linux Kernel.pdf](https://www.slideshare.net/AdrianHuang/memory-compaction-in-linux-kernelpdf), the test scenario was done with `stress-ng`
    - So i wanted to test it with same approach. (Of course, the kernel version is significantly different. 5.11 vs 6.6)
    
    ---
    
    <details><summary>stress-ng analyze</summary>
    
    - Let’s check it from GDB.
        
        ```c
        gdb stress-ng
        run --vm 8 --vm-bytes 80% -t 10m
        ```
        
        - Because of `fork` , it is detached.
            
            ![image](https://github.com/JongHoB/Memory_Compaction_Test/assets/78012131/478efc87-0c8f-4f8f-8152-8416767d2736)
            
        - https://woosunbi.tistory.com/94 : Need to set child process debugging
        - **BUT……………………..There is no symbol!**
            - **I tried to compile the program with debug option(-g, -ggdb). But there are errors…….**
        - *FIX!* (I modify the `stress-vecwide.c` (took hours…..😱))
            - `stress-ng --vm 1 --vm-bytes 80% -t 10m`
            - `stress_run_parallel` →`stress_run` → `rc = g_stressor_current->stressor->info->stressor(&args);` :1439 → (stressor function) `stress-vm.c : stress_vm()`  → `stress_oomable_child` → `(func(args,context))stress_vm_child` → `stress_vm_all` → `mmap`
            
            ```c
            buf = (uint8_t *)mmap(NULL, buf_sz,
            					PROT_READ | PROT_WRITE,
            					MAP_PRIVATE | MAP_ANONYMOUS |
            					vm_flags, -1, 0);
            ```

            - It allocates memory with `mmap`.
    
    ---

    - Maybe I need to change the command option.
    - From the presentation pdf, it has too many features….
        - https://github.com/ColinIanKing/stress-ng/blob/master/presentations/kernel-recipes-2023/kernel-recipes-2023.pdf
        - https://events.linuxfoundation.org/wp-content/uploads/2022/10/Colin-Ian-King-Mentorship-Stress-ng.pdf
    - In example folder of stress-ng  package , i can find some examples in `memory.job` and `vm.job`
    
    </details>
