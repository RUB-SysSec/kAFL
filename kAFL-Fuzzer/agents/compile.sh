printf "\nlinux_x86_64 userspace components...\n"
echo "------------------------------------"
cd linux_x86_64
bash compile.sh
cd ../

printf "\nmacOS_x86_64 userspace components...\n"
echo "------------------------------------"
cd macOS_x86_64
bash compile.sh
cd ../

printf "\nwindows_x86_64 userspace components...\n"
echo "------------------------------------"
cd windows_x86_64
bash compile.sh
cd ../

printf "\ndone...\n"
