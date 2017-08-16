/* 
 * KVM-PT userspace support test program
 * (c) Sergej Schumilo, 2016 <sergej@schumilo.de> 
 * 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define KVM_VMX_PT_SUPPORTED	_IO(KVMIO,	0xe4)

int main(){
	int kvm, ret;

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm == -1){
		printf("ERROR: KVM is not loaded!\n");
		exit(1);
	} 

	ret = ioctl(kvm, KVM_VMX_PT_SUPPORTED, NULL);
	if (ret == -1){
		printf("ERROR: KVM-PT is not loaded!\n");
		exit(2);
	}
	if (ret == -2){
		printf("ERROR: Intel PT is not supported on this CPU!\n");
		exit(3);
	}
	printf("KVM-PT is ready!\n");
	return 0;
}
