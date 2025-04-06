# Soquete - Hacky Websockets

This is a **pure Go WebSocket client** implementation designed to pass the [Autobahn WebSocket Test Suite](https://github.com/crossbario/autobahn-testsuite)'s `fuzzingserver` in **echo mode**. 

I tested it with a real websocket server too and it seems to work.

It's all very hacky and ugly but somehow it seems to work.

I had to stay awake while accompanying a municipal scavenger hunt event (gincana em português) so to pass the time I implemented this.

## Features

- Almost Full WebSocket handshake implementation
- Masking/unmasking logic
- UTF-8 validation for text frames with partial suport for fail-fast
- Fragmentation support (incl. continuation frames)
- Control frame validation (Ping/Pong/Close)
- (Maybe correct) close frame handling and validation
- Error handling

## Usage

1. **Run the [Autobahn fuzzingserver](https://github.com/crossbario/autobahn-testsuite)** locally:

```bash
docker run -it --rm -v ${PWD}/config:/config -v ${PWD}/reports:/reports crossbario/autobahn-testsuite
```

You should configure `config/fuzzingserver.json` to expect an agent named `"echo"`.

2. **Run the Go client:**

```bash
go run main.go
```

It will:

- Connect to the fuzzingserver
- Run all test cases from `/getCaseCount`
- Execute them via `/runCase?case=...`
- Send results to `/updateReports?agent=echo`

3. **Check your test results** in the `reports/clients/index.html` file.

## Notes

- Add TLS support by simply changing the conn to a `tls.Conn` instance. 
- Not a lib. Yet...
