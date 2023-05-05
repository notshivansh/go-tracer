# go-tracer

To run:
1. make the docker image by rumming the command ```docker build . -t aktosecurity/ebpf```
2. run the script "initial_script.sh". This script sets the path and version information for openssl and boring ssl (bssl)
3. Set the akto-kafka URL in ebpf.env
4. run ```docker-compose up -d```

Voila.. EBPF delpoyed