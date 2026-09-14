# Xray Chitanda large-write EOF fix

This fix requires updating **Xray servers accepting Chitanda inbound traffic**.
Existing Mihomo / OpenClash / Clash Verge / CMFA clients remain wire-compatible
and do not need an update for this bug. The automated release workflow may
still build both cores; that does not make the Mihomo update mandatory.

Xray v26.3.27's `buf.BufferedWriter.Write` returns `ErrBufferFull` when one
write exceeds its 8192-byte buffer. Chitanda's valid RawStream frames can carry
32768 bytes, so the previous adapter aborted transfers once larger writes
arrived. This affects large AI requests and ordinary transfers, not just SSE.

The adapter now copies input into owned Xray buffers with `buf.MergeBytes`
and sends them through the dispatcher's native `WriteMultiBuffer` interface.
It propagates downstream errors immediately, without a separate buffered
flush whose failure could be lost. Encryption, frame format, credentials,
32 KiB frames, and client settings are unchanged.

Regression coverage runs against the injected Xray adapter before release:

- 8191 / 8192 / 8193-byte boundaries through 2 MiB writes;
- payload ownership after caller buffer reuse;
- downstream write-error propagation and half-close draining;
- an encrypted RawStream upload exceeding the SDK's 1 MiB ramp-up threshold,
  followed by another message on the same connection.

Use an artifact from the workflow run containing this fix, not a cached file
identified only by the upstream version: automated rebuilds can keep the same
upstream version and asset name. Verify the new artifact checksum before a
separate, backed-up server deployment. Building a package does not update any
running server automatically.
