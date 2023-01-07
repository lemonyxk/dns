# dns

```shell
# dns server listening on 192.168.0.3
# *.server.com to 192.168.0.2
dns --domain "*.server.com:192.168.0.2" --addr 192.168.0.3

# set default dns server
dns --domain "*.server.com:192.168.0.2" --addr 192.168.0.3 --default 8.8.8.8

# use config file
echo "*.server.com 192.168.0.2" > config.txt
dns --config config.txt --addr 192.168.0.3 --default 8.8.8.8

# simple
# dns server listening on 127.0.0.1
dns -d "*.server.com:192.168.0.2"
```

- Linux and windows need set dns server ip to you network.
- MacOS will do it automatic.