# Vulnerability Verification Verdicts

## Claim A: Permanent Funds Lock via Malformed Acknowledgement
**Verdict: VALID & ELIGIBLE**

**Analysis**:
- **Mechanism**: The `transfer` module's `OnAcknowledgementPacket` callback performs `UnmarshalJSON` on the acknowledgement bytes. If this fails (e.g., counterparty sends random bytes), it returns an error.
- **Impact**: In `ibc-go` core `AcknowledgePacket`, if the application callback returns an error, the entire transaction reverts. This prevents the deletion of the packet commitment.
- **Result**: The packet remains in the `Committed` state on the source chain. Since a valid proof of acknowledgement exists (provided by the counterparty), the packet cannot be timed out. The user's funds remain in escrow indefinitely.
- **Eligibility**: While it requires a malicious counterparty, this is a valid threat model for IBC (users trust the bridge code, not the counterparty's logic). The bridge should fail-safe (e.g., treat bad ack as error-ack) rather than bricking funds.
- **PoC**: Runnable Go test provided in `POC/ibc-ack`.

## Claim B: Authz Recursion Fatal Stack Overflow
**Verdict: FALSE POSITIVE / MITIGATED**

**Analysis**:
- **Mechanism**: `MsgExec` handler (`Exec`) allows execution of nested `MsgExec` messages without an explicit depth check in the handler loop.
- **Mitigation**: The Proto unmarshaller in Cosmos SDK (`v0.50+` and specifically `v0.53.5` checked) enforces a `max depth exceeded` error when decoding deeply nested structures (around depth 100-200).
- **PoC Result**: A test constructing a nested message of depth 2000 failed at the `Unmarshal` step with `max depth exceeded`.
- **Conclusion**: The attack vector is closed at the wire decoding level. It is not exploitable remotely.

## Claim C: ICA Host DoS (No Gas Limit)
**Verdict: FALSE POSITIVE (Gas Metered)**

**Analysis**:
- **Mechanism**: The ICA Host `OnRecvPacket` executes messages via `executeTx`.
- **Gas**: The execution context uses `ctx.CacheContext()`, which inherits the `GasMeter` from the parent context. The parent context is gas-metered by `baseapp` based on the Relayer's transaction.
- **Result**: Execution is fully gas-metered. If an attacker packs too many messages, the Relayer's transaction runs out of gas and fails.
- **Conclusion**: This is a griefing vector against Relayers (who pay the fees), not a DoS against the node itself. Relayers can mitigate this via simulation and configuration.
