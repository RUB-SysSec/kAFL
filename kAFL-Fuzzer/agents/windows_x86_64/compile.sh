if [[ "$OSTYPE" == "linux-gnu" ]]; then
	if x86_64-w64-mingw32-gcc -v 2> /dev/null && x86_64-w64-mingw32-g++ -v 2> /dev/null; then
		printf "\tCompiling loader...\n"
		x86_64-w64-mingw32-g++ info/info.cpp -o info/info.exe -lntdll -lpsapi
		printf "\tCompiling info executable...\n"
		x86_64-w64-mingw32-gcc loader/loader.c -o loader/loader.exe -Wall -lpsapi
		printf "\tCompiling vuln_driver fuzzer...\n"
		x86_64-w64-mingw32-gcc fuzzer/vuln_test.c -o fuzzer/vuln_test.exe

	else
		printf "\tError: x86_64-w64-mingw32-gcc/g++ not found. Please install x86_64-w64-mingw32-gcc/g++ (sudo apt install gcc-mingw-w64-x86-64  g++-mingw-w64-x86-64)!\n"
	fi 
else
	printf "\tError: Cannont compile windows userspace components on this plattform!\n\tPlease use Linux instead!\n"
fi


# sudo apt install gcc-mingw-w64-x86-64
# sudo apt install gcc-mingw-w64-x86-64
# linux_x86-64-2$ x86_64-w64-mingw32-gcc -v
