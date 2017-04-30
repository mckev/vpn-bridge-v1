#!/bin/bash
machine=`uname -m`
if [ "$machine" == "i686" -o "$machine" == "x86_64" ]; then
	echo "i686"
	gcc -m32 -Wall -O3 -o common.o    -c common.c    -I. -Icore_apr -Icore_apr/include/linux
	gcc -m32 -Wall -O3 -o vclient.o    -c vclient.c    -I. -Icore_apr -Icore_apr/include/linux
	gcc -m32 -Wall -O3 -o vserver.o    -c vserver.c    -I. -Icore_apr -Icore_apr/include/linux
	gcc -m32 -Wall -O3 -o vclient    common.o vclient.o    core_apr/lib/linux32/libaprutil-1.a core_apr/lib/linux32/libapr-1.a    -lpthread
	gcc -m32 -Wall -O3 -o vserver    common.o vserver.o    core_apr/lib/linux32/libaprutil-1.a core_apr/lib/linux32/libapr-1.a    -lpthread

elif [ "$machine" == "armv6l" ]; then
	echo "armv6l"
	gcc -Wall -Ofast -o common.o    -c common.c    -I. -Icore_apr -Icore_apr/include/linux
	gcc -Wall -Ofast -o vclient.o    -c vclient.c    -I. -Icore_apr -Icore_apr/include/linux
	gcc -Wall -Ofast -o vserver.o    -c vserver.c    -I. -Icore_apr -Icore_apr/include/linux
	gcc -Wall -Ofast -o vclient    common.o vclient.o    -laprutil-1 -lapr-1
	gcc -Wall -Ofast -o vserver    common.o vserver.o    -laprutil-1 -lapr-1

else
	echo "Unsupported processor $machine"
fi

