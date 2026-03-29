## Bottom line

I don’t think your remaining blocker is the global crypto anymore.

**Mac working at MB scale is very strong evidence that:**
- FakeTLS auth is basically correct,
- the client↔proxy and proxy↔DC key derivation is basically correct,
- the relay loop is no longer fundamentally broken.

So the remaining iPhone issue is most likely in the **connection lifecycle right after `ServerHello`**, not in `buildServerHello()` or the core CTR formulas.

## Most likely root cause

Your code still makes this desktop-friendly assumption:

> **After `ServerHello`, the first TLS Application Data record arrives quickly, and it contains the full 64-byte MTProto obfuscation handshake, optionally followed by pipelined data.**

That assumption is here:

```zig
const payload_len = std.mem.readInt(u16, tls_header[3..5], .big);
if (payload_len < constants.handshake_len) return;
...
const handshake: *const [constants.handshake_len]u8 = payload_buf[0..constants.handshake_len];
```

and it is combined with this:

```zig
setRecvTimeout(fd, active_timeout_sec); // 10s
```

which is applied **before**:
- finishing the TLS bootstrap,
- receiving the client’s MTProto obfuscated handshake,
- and before you know whether the socket is a real session or just an iOS warmed connection.

### Why this matches the symptoms

- **iPhone proxy settings show “Connected”**  
  So FakeTLS auth and at least one minimal round-trip are fine.

- **Mac fully works**  
  So your universal crypto path is not globally wrong.

- **iPhone opens lots of idle/warmed connections**  
  That means its timing/fragmentation behavior is different from Desktop.

- **Some iPhone connections exchange tens of KB but never become real sessions**  
  That’s exactly what you’d expect if:
  - proxy test / lightweight channels work,
  - but the main pooled session connections are being dropped or malformed during the post-ServerHello bootstrap.

---

## What I think is happening

### 1. You start the “active” timeout too early
Right now the $10$s timeout starts after the **first byte** of the TCP connection.

For Desktop that’s fine because it usually does the whole sequence promptly.

For iOS, that is too early. iOS is much more likely to:
- pre-open a connection,
- send ClientHello,
- validate proxy reachability,
- then delay the first MTProto AppData,
- or split it differently.

So you’re likely killing some of the connections iOS actually intends to reuse.

---

### 2. You require the initial MTProto handshake to fit in one TLS AppData record
That is not guaranteed.

If iPhone splits the first $64$ obfuscated bytes across two TLS Application Data records, your code silently drops the connection.

Desktop may happen to put those $64$ bytes in one record often enough that you never noticed.

This is the **single most concrete code-level incompatibility** still in the handshake path.

---

### 3. Your remaining S2C shaping may still be too aggressive for iOS
I do **not** think this is the first thing to fix, but it is the next suspect after handshake-lifecycle issues.

Your `DynamicRecordSizer` ramps to $16384$-byte TLS records. Desktop likely doesn’t care. iOS may be less happy with large fake-TLS records, especially early in a connection.

Even if the client *should* tolerate them, your current goal is compatibility, not elegance.

---

## What I would fix first

# 1) Don’t arm the 10s timeout until after the full MTProto handshake is assembled

For a first production fix, simplest is:

- keep the long idle tolerance through:
  - ClientHello,
  - ServerHello,
  - CCS,
  - and until you have the full $64$-byte MTProto obfuscation handshake.
- only then proceed into the non-blocking relay.

For testing, I would even temporarily remove the 10s recv timeout from the handshake phase entirely.

### Why
Because the current timeout policy is iOS-hostile *specifically* in the place where iOS behaves differently from Desktop.

---

# 2) Assemble the 64-byte MTProto handshake across multiple TLS AppData records

This is the main concrete patch.

Instead of:

```zig
if (payload_len < constants.handshake_len) return;
const handshake: *const [constants.handshake_len]u8 = payload_buf[0..constants.handshake_len];
```

you want:

- skip CCS records,
- read AppData records until you have exactly $64$ bytes of obfuscated handshake,
- keep any extra bytes from the record that completed the $64$ bytes as pipelined payload.

That makes the proxy robust to iOS fragmentation without changing your crypto.

---

# 3) Temporarily disable DRS ramp for compatibility testing

For now, keep S2C TLS records fixed and small:
- either `1369`,
- or `4096`.

Do **not** ramp to `16384` until iPhone works.

This is a compatibility simplifier, not a proven root cause.

---

## Minimal patch direction

<details>
<summary>Patch sketch for initial MTProto handshake assembly</summary>

```zig
const handshake_timeout_sec: u32 = 60;

const InitialClientHandshake = struct {
    wire_handshake: [constants.handshake_len]u8,
    pipelined_len: usize,
    pipelined_buf: [constants.max_tls_ciphertext_size]u8,
    app_records_used: u8,
};

fn readInitialClientHandshake(stream: net.Stream) !InitialClientHandshake {
    var out: InitialClientHandshake = .{
        .wire_handshake = undefined,
        .pipelined_len = 0,
        .pipelined_buf = undefined,
        .app_records_used = 0,
    };

    var hs_pos: usize = 0;
    var tls_header: [5]u8 = undefined;
    var body_buf: [constants.max_tls_ciphertext_size]u8 = undefined;

    while (hs_pos < constants.handshake_len) {
        if (try readExact(stream, &tls_header) < 5) return error.ConnectionReset;

        const record_type = tls_header[0];
        const body_len = std.mem.readInt(u16, tls_header[3..5], .big);
        if (body_len > constants.max_tls_ciphertext_size) return error.ConnectionReset;

        switch (record_type) {
            constants.tls_record_change_cipher => {
                if (body_len > 256) return error.ConnectionReset;
                if (try readExact(stream, body_buf[0..body_len]) < body_len) {
                    return error.ConnectionReset;
                }
            },
            constants.tls_record_application => {
                if (try readExact(stream, body_buf[0..body_len]) < body_len) {
                    return error.ConnectionReset;
                }

                out.app_records_used += 1;

                const need = constants.handshake_len - hs_pos;
                const take = @min(need, body_len);

                @memcpy(out.wire_handshake[hs_pos..][0..take], body_buf[0..take]);
                hs_pos += take;

                if (body_len > take) {
                    const extra = body_len - take;
                    @memcpy(out.pipelined_buf[0..extra], body_buf[take..][0..extra]);
                    out.pipelined_len = extra;
                    break;
                }
            },
            constants.tls_record_alert => {
                if (body_len > 256) return error.ConnectionReset;
                _ = try readExact(stream, body_buf[0..body_len]);
                return error.ConnectionReset;
            },
            else => return error.ConnectionReset,
        }
    }

    return out;
}
```

Then in `handleConnectionInner()`:

```zig
// after first byte arrives
setRecvTimeout(fd, handshake_timeout_sec);

// ... ClientHello read/validate ...

try writeAll(client_stream, server_hello);

const initial = try readInitialClientHandshake(client_stream);

log.info("[{d}] ({s}) Initial MTProto handshake assembled from {d} AppData record(s), pipelined={d}B", .{
    conn_id, peer_str, initial.app_records_used, initial.pipelined_len,
});

const handshake: *const [constants.handshake_len]u8 = &initial.wire_handshake;
```

And later:

```zig
var initial_c2s_bytes: u64 = 0;

if (initial.pipelined_len > 0) {
    const pipelined = initial.pipelined_buf[0..initial.pipelined_len];
    client_decryptor.apply(pipelined);
    tg_encryptor.apply(pipelined);
    try writeAll(dc_stream, pipelined);
    initial_c2s_bytes = pipelined.len;
}
```

</details>

---

## Why I think this is higher-value than more crypto digging

Because the current evidence says:

- **Mac MB-scale success** means your crypto is not broadly wrong.
- **iPhone “Connected”** means the FakeTLS auth path is not broadly wrong.
- That leaves **timing / fragmentation / connection pooling behavior** as the main delta.

And the code currently has a clear iOS-hostile assumption in exactly that area.

---

## What I would *not* spend more time on first

I would deprioritize:
- `buildServerHello()` again,
- HMAC scope again,
- timestamp XOR again,
- DC CTR math again.

Those were good fixes, but they are no longer the most likely problem.

---

## Secondary suspect: S2C shaping

If the handshake-lifecycle patch above does **not** fix iPhone, then my next move would be:

### Freeze S2C TLS records at a small fixed size
Temporarily make:

```zig
const DynamicRecordSizer = struct {
    fn init() DynamicRecordSizer {
        return .{
            .current_size = 1369,
            .records_sent = 0,
            .bytes_sent = 0,
        };
    }

    fn nextRecordSize(self: *DynamicRecordSizer) usize {
        _ = self;
        return 1369; // fixed for compatibility test
    }

    fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        _ = self;
        _ = payload_len;
    }
};
```

If iPhone suddenly starts syncing, then the remaining issue is your fake-TLS S2C recordization, not the MTProto crypto.

---

## Tertiary suspect: your non-FAST_MODE S2C path

I agree that non-FAST_MODE is theoretically valid.

But pragmatically, if iPhone still fails after fixing handshake timing/fragmentation, then the fastest route to a production fix is:

### Add canonical `FAST_MODE` as a toggle
Because that gives you:
- parity with the canonical Python proxy’s default behavior,
- less S2C machinery,
- less chance of a subtle S2C keystream mismatch.

So I would treat FAST_MODE as the **best A/B test** after the handshake patch, not as the first fix.

---

## Very useful low-overhead instrumentation

Do **not** add hot-path hex dumps again.

Instead add only these:

### Handshake-stage logs
These are cheap and very informative:
- short read while reading ClientHello body,
- short read while waiting for post-ServerHello TLS record,
- number of AppData records needed to assemble the initial $64$ bytes,
- pipelined bytes size.

If iPhone often needs `2+` AppData records and Mac uses `1`, you found it.

---

### TLS Alert body logging
Right now `relayClientToDc()` treats TLS Alert as just reset.

Instead log the body once:

```zig
if (record_type == constants.tls_record_alert) {
    const alert_len = std.mem.readInt(u16, tls_hdr_buf[3..5], .big);
    var alert_buf: [256]u8 = undefined;

    if (alert_len <= alert_buf.len and
        try readExact(client, alert_buf[0..alert_len]) == alert_len and
        alert_len >= 2)
    {
        log.info("[{d}] C2S TLS Alert level={d} desc={d}", .{
            conn_id, alert_buf[0], alert_buf[1],
        });
    }

    return error.ConnectionReset;
}
```

### Why this matters
If iPhone starts sending TLS alerts right after first S2C:
- the client is actively rejecting your fake-TLS stream,
- which points to S2C recordization or S2C crypto.

If there are **no** alerts and instead you see handshake-stage short reads:
- it’s timing/fragmentation/pooling.

---

## One more important interpretation

Some failed Mac connections are probably **normal loser/speculative connections**.

Telegram clients race and abandon sockets. So:
- don’t chase every `polls=2 c2s=0 s2c≈154` on Mac,
- chase the fact that **Mac has at least one connection that goes MB-scale, while iPhone never does**.

That means the remaining bug is likely affecting a connection style that Desktop can recover from but iOS cannot.

---

## My recommended order

1. **Move the handshake timeout later**  
   Don’t use the $10$s timeout until the full $64$-byte MTProto handshake has been assembled.

2. **Support fragmented initial MTProto handshake across multiple TLS AppData records**  
   This is the most concrete code bug still present.

3. **Disable DRS ramp**  
   Fixed small S2C records for compatibility testing.

4. **Add handshake-stage short-read logging + TLS alert logging**

5. **If iPhone still fails: add FAST_MODE toggle**  
   That becomes the fastest route to production parity.

---

## My confidence

- **High confidence** that the current post-ServerHello state machine is still too Desktop-specific.
- **Medium-high confidence** that fixing handshake timing + fragmented initial AppData handling will improve iPhone materially.
- **Medium confidence** that if anything remains after that, it will be S2C shaping or the non-FAST_MODE path.

If you want, I can turn this into a **single ready-to-paste patch for `src/proxy/proxy.zig`** with:
- fragmented initial-handshake assembly,
- later timeout arming,
- fixed-size S2C TLS records,
- and TLS alert logging.