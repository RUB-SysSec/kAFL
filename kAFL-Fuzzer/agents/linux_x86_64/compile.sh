if [[ "$OSTYPE" == "linux-gnu" ]]; then
	printf "\tCompiling loader...\n"
	gcc loader/loader.c -o loader/loader
	printf "\tCompiling info executable...\n"
	gcc info/info.c -o info/info
	printf "\tCompiling vuln_driver fuzzer...\n"
	gcc fuzzer/kafl_vuln_test.c -o fuzzer/kafl_vuln_test
	printf "\tCompiling EXT4 fuzzer...\n"
	gcc fuzzer/fs_fuzzer.c -o fuzzer/ext4 -D EXT4
	printf "\tCompiling NTFS fuzzer...\n"
	gcc fuzzer/fs_fuzzer.c -o fuzzer/ntfs -D NTFS
	printf "\tCompiling FAT fuzzer...\n"
	gcc fuzzer/fs_fuzzer.c -o fuzzer/fat -D FAT32
else
	printf "\tError: Cannont compile linux userspace components on this plattform!\n\tPlease use Linux instead!\n"
fi
