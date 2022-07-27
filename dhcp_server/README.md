## dhcp server

### Prerequisite

```
sudo apt install libsqlite3-dev sqlite3
```

```
CREATE TABLE "lease_entries" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"mac_addr" TEXT NOT NULL UNIQUE,
	"ip_addr" TEXT NOT NULL,
	"deleted" unsigned INTEGER NOT NULL DEFAULT 0
);
```

### Memo

https://github.com/teru01/dhcp_server
