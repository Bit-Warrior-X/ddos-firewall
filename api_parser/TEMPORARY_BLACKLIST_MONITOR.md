# Temporary Blacklist Monitor (api_parser)

The api_parser monitors the Redis temporary blacklist and notifies the backend when a **new item is added**.

## How it works

1. **OpenResty (nginx)** writes each new temporary blacklist entry to Redis (SET key + EXPIRE) and **PUBLISHes** the entry JSON to the channel **`temporaryblacklist:added`**.
2. A background thread in api_parser **subscribes** to that channel. When a message arrives (the JSON payload), it POSTs the same JSON to the backend at **`TEMPORARY_BLACKLIST_NOTIFY_URL`**.

So the backend is informed as soon as a new entry is added, with no dependency on Redis keyspace notifications. **Two monitors** can use the same Redis: acl_manager.lua subscribes to `acl:updates` and `__keyevent@0__:*` for ACL rule keys; api_parser subscribes only to `temporaryblacklist:added`.

## Configuration

- **`config.TEMPORARY_BLACKLIST_NOTIFY_URL`**  
  Default: `{API_BASE_URL}/temporary_blacklist_added`  
  Backend must implement this endpoint and accept the JSON body (one temporary blacklist entry).

## Backend endpoint

**POST** `{API_BASE_URL}/temporary_blacklist_added`

**Request body (JSON)** – one entry, same shape as stored in Redis:

```json
{
  "ip": "192.168.1.1",
  "url": "/api/foo",
  "country": "United States",
  "city": "New York",
  "blocked_at": "1729876543",
  "ttl": 180,
  "trigger_rule": "intervalfreqlimit"
}
```

The backend can use this to insert/update the same row in MySQL or to trigger any other logic when a new temporary blacklist entry is added.

## Coexistence with acl_manager.lua

Both can monitor the same Redis instance:

- **acl_manager.lua** (OpenResty): subscribes to channel `acl:updates` and pattern `__keyevent@0__:*`. It only reacts when the key name is an ACL rule (e.g. `whitelist`, `blacklist`). Keys like `temporaryblacklist:ip:ts` are ignored by acl_manager.
- **api_parser**: subscribes only to channel `temporaryblacklist:added`. Nginx explicitly PUBLISHes to this channel when it adds an entry, so no Redis keyspace configuration is required.
