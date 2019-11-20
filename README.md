# stm32_websocket_client
Websocket Client using mbedtls

## Prerequisites
Set up a Project for your STM32 Microcontroller with LWip and mbedTLS 
For example:
 - https://github.com/STMicroelectronics/STM32CubeF4/tree/master/Projects/STM324x9I_EVAL/Applications/mbedTLS/SSL_Client
 - https://github.com/anon767/STM32F7HTTPS
 
Also you need:
- openssl
- golang (for the test websocket server)

## Usage
1. Adjust the client.h
2. In your main.c
```C
#include client.h
```

and call

```C
SSL_Client();
```
Somewhere in you main();

3. Generate Cert/Key and build and start server
```bash
mkdir -p $GOPATH/src/github.com/anon767/wsserver
cp ./test_server.go $GOPATH/src/github.com/anon767/wsserver/wsserver.go
cd $GOPATH/src/github.com/anon767/
go get && go build
chmod +x wsserver
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
./wsserver
```

4. Compile and Flash your device
