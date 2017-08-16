/*

Copyright (C) 2017 Sergej Schumilo

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/mount.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../../kafl_user.h"

#define KAFL_TMP_FILE	"/dev/shm/trash"

#include <linux/version.h>
#include <linux/loop.h>

static inline void kill_systemd(void){
	system("systemctl disable systemd-udevd");
	system("systemctl stop systemd-udevd");
	system("systemctl stop systemd-udevd-kernel.socket");
	system("systemctl stop systemd-udevd-control.socket");

	system("/lib/systemd/systemctl disable systemd-udevd");
	system("/lib/systemd/systemctl stop systemd-udevd");
	system("/lib/systemd/systemctl stop systemd-udevd-kernel.socket");
 	system("/lib/systemd/systemctl stop systemd-udevd-control.socket");
}

int main(int argc, char** argv)
{
	struct stat st = {0};
	int fd, ret;
	char loopname[4096];
	int loopctlfd, loopfd, backingfile;
    	long devnr;

	kAFL_payload* payload_buffer = mmap((void*)NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(payload_buffer, 0xff, PAYLOAD_SIZE);

	kill_systemd();

	system("mkdir /tmp/a/");
	loopctlfd = open("/dev/loop-control", O_RDWR);
	devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	sprintf(loopname, "/dev/loop%ld", devnr);
	close(loopctlfd);

	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload_buffer);

	loopfd = open(loopname, O_RDWR);
	backingfile = open(KAFL_TMP_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);
	ioctl(loopfd, LOOP_SET_FD, backingfile);

	while(1){
		
		lseek(backingfile, 0, SEEK_SET);
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		write(backingfile, payload_buffer->data, payload_buffer->size-4);
		ioctl(loopfd, LOOP_SET_CAPACITY, 0);

		kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);  
#ifdef EXT4
		ret = mount(loopname, "/tmp/a/", "ext4", payload_buffer->data[payload_buffer->size-4], NULL);
#elif NTFS
		ret = mount(loopname, "/tmp/a/", "ntfs", payload_buffer->data[payload_buffer->size-4], NULL);
#elif FAT32 
		ret = mount(loopname, "/tmp/a/", "msdos", payload_buffer->data[payload_buffer->size-4], NULL);
#endif
		if(!ret){
			mkdir("/tmp/a/trash", 0700);
			stat("/tmp/a/trash", &st);
        	umount2("/tmp/a", MNT_FORCE);
        	}
        	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
	close(backingfile);
    return 0;
}

