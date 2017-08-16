#ifndef __VMX_H__
#define __VMX_H__

#include <linux/types.h>
#include <linux/uaccess.h>

struct vcpu_vmx;
void add_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr, u64 guest_val, u64 host_val);

#endif

