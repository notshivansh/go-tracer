# go-tracer

To run:
1. make the docker image by rumming the command ```docker build . -t aktosecurity/ebpf```
2. run the script "initial_script.sh". This script sets the path and version information for openssl and boring ssl (bssl)
3. Set the akto-kafka URL in ebpf.env
4. run ```docker-compose up -d```

Voila.. EBPF delpoyed

Notes:

"iov" releated headers are not added 

The current working image is created using alpine:3.18, and works smoothly.
To implement multistage builds: https://faun.pub/the-martial-arts-of-writing-go-dockerfile-9dcffd010619

The code taken from mirror-api-logging is in parser.go (tryReadFromBD() function has been taken as is with some modification to the arguments) and main.go (initKafka() function).

bcc wrappers and other utility functions are from https://github.com/DataDog/ebpf-training and have been modified for our use case.

A specific version of iovisor/bcc library is being used, reason and problem : https://stackoverflow.com/questions/73714654/not-enough-arguments-in-call-to-c2func-bcc-func-load
