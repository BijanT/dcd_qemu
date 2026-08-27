system_ss.add(when: libbpf, if_true: files('ebpf.c', 'ebpf_rss.c'), if_false: files('ebpf_rss-stub.c'))
system_ss.add(when: bpf_fault, if_true: files('ebpf_bpf_fault.c'), if_false: files('ebpf_bpf_fault-stub.c'))
