# network-programming-with-rust

1. Run `cp .env{.sample,}`

2. Check local ip addr of your machine by `ip addr`. In my environment, it is `wlo1`

3. Edit your `MY_IPADDR` to ip checked at 2

4. `cargo run`

5. `sudo ../target/debug/port-scanner 192.168.1.1 sS` (192.168.1.1 may be your WiFi router)


## The result

```sh
> sudo ../target/debug/port-scanner 192.168.11.1 sS
[2022-01-07T13:22:43Z INFO  port_scanner] start send_packet
port 53 is open
port 80 is open
port 443 is open
port 444 is open
[2022-01-07T13:22:47Z INFO  port_scanner] end send_packet
```

![Screenshot from 2022-01-07 22-32-30](https://user-images.githubusercontent.com/13580199/148551405-6c3b075d-10b3-404e-a2bb-59320b570cf9.png)
