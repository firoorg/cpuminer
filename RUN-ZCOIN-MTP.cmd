
rem x64\Release\cpuminer -a mtp -o  http://127.0.0.1:8382   -u djm34 -p password --coinbase-addr aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak -t 1  --no-getwork --protocol-dump

x64\Release\cpuminer -a mtp -o  stratum+tcp://zcoin.mintpond.com:3000 -u aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak.cpuworker  -p 0,d=5,verbose,strict -t 6  --cpu-affinity 0xff

rem x64\Release\cpuminer -a mtp -o  stratum+tcp://pool.bibop.net:4000 -u aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak.worker  -p c=XZC -t 3 

pause