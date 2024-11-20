# mynat

mynat is a command line tool to determine the NAT type being passed during communication.

This tool is based on [RFC4787](https://datatracker.ietf.org/doc/html/rfc4787) and [RFC5780](https://datatracker.ietf.org/doc/html/rfc5780).

## usage

```shell
go run ./cmd/mynat/main.go

# options
  #  -h    command usage help
  #  -i    target network interface of inspection (default "en0")
  #  -v    verbose

```
