# go-tracer

To run:
1. make the docker image by rumming the command ```docker build . -t aktosecurity/ebpf```
2. run the script "initial_script.sh". This script sets the path and version information for openssl and boring ssl (bssl)
3. Set the akto-kafka URL in ebpf.env
4. run ```docker-compose up -d```

Voila.. EBPF delpoyed

Notes:

"iov" releated headers are not added 

The current working image is created using alpine:edge, and works smoothly. 
Doesn't work out of the box for alpine:latest, or golang:1.20-alpine (do "apk add gcc g++" before building the golang project). 
Clues till now: 
1. golang:1.20-alpine, doesn't have some preinstalled libraries which alpine:edge has (I figured gcc & g++ were among them, but more seem to be missing)
2. By default any version of alpine besides alpine:edge installs go version less than 1.20, which are not able to run the core project. Building golang 1.20 from source on alpine:3.17 (latest) in a docker container with host volumes, also doesn't work out of the box. (run "ldd $(which go)" to see the problem). The fix for that is here: ( https://github.com/golang/go/issues/59305, https://gitlab.alpinelinux.org/alpine/aports/-/issues/14846 ). This does install go 1.20, but still gives error while running the go build. 
3. go 1.20 notes: https://tip.golang.org/doc/go1.20
4. Also, alpine uses "musl c" and not gcc as its standard c library.

Couldn't figure out what alpine:edge has and is needed but missing here. I was in the process of fixing this, since alpine:edge is a beta build. Though, this is not an issue right now, but might be one in the future, since alpine:edge is a beta build and might change over time.
If this does become a problem or a problem not worth solving, a really simple fix would be to change the base image to some other os (ubuntu) and use  multistage builds in dockerfile to only ship the go built binary (will reduce the size very much, also the only reason why using alpine in the first place). To implement multistage builds: https://faun.pub/the-martial-arts-of-writing-go-dockerfile-9dcffd010619

The code taken from mirror-api-logging is in parser.go (tryReadFromBD() function has been taken as is with some modification to the arguments) and main.go (initKafka() function).

bcc wrappers and other utility functions are from https://github.com/DataDog/ebpf-training and have been modified for our use case.

A specific version of iovisor/bcc library is being used, reason and problem : https://stackoverflow.com/questions/73714654/not-enough-arguments-in-call-to-c2func-bcc-func-load
