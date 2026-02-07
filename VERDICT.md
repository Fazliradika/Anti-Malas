# Verification Verdict: Permanent Funds Lock via Malformed IBC Acknowledgement

## Verdict
**VALID & ELIGIBLE** (High Severity)

## Justification
The vulnerability allows a malicious or malfunctioning counterparty chain to permanently lock user funds on the source chain by returning a malformed acknowledgement (e.g., non-JSON bytes).
- **Code verification** confirms that `ibc-go` (ICS-20) `OnAcknowledgementPacket` returns an error on `UnmarshalJSON` failure.
- **Core logic verification** confirms that this error causes `AcknowledgePacket` to revert, skipping `deletePacketCommitment`.
- **Timeout logic verification** confirms that `TimeoutPacket` cannot be called because a valid proof of acknowledgement (receipt) exists on the counterparty.
- **PoC** confirms that the packet commitment remains "stuck" on the source chain, leading to permanent loss of control over the escrowed funds.
- **Eligibility**: While this requires a malicious counterparty, it violates the "robustness" expectation of the IBC protocol. A user trusting the *source* chain and the *bridge protocol* should not have their funds locked solely because the *destination* chain acted maliciously. The correct behavior should be to fail-safe (clear the commitment, even if funds are lost on the other side, or error-ack).

## Tested Environment
- **ibc-go**: `v10.5.0` (Commit: `7d118601a5977a48a1c1f2eb92c88bc227a042c9`)
- **cosmos-sdk**: `v0.53.5` (Commit: `ce4632d08c562ca8e90d5a050965f1f4fd8f8543`)
- **cometbft**: `v0.38.20` (Commit: `c96f26503c041bb39fdc93297e3b2fd6d10ba9d8`)

## HackerOne Report Draft

### Summary
A logic flaw in the IBC `transfer` module (ICS-20) allows a counterparty chain to permanently lock user funds on the source chain. By writing malformed bytes (e.g., invalid JSON) to the acknowledgement path, the counterparty triggers an error in the source chain's `OnAcknowledgementPacket` callback. This error propagates to the core IBC handler, reverting the transaction and preserving the packet commitment. Since the packet has been proven to be acknowledged/received, it cannot be timed out. The packet enters a permanent "stuck" state.

### Technical Details
1. **Source Chain (Chain A)**: Sends a transfer packet. Funds are escrowed. Packet commitment is stored.
2. **Dest Chain (Chain B)**: Receives packet. Instead of a valid JSON Ack, it writes `0xDEADBEEF` (or any non-unmarshalable bytes) to the acknowledgement store.
3. **Relayer**: Submits `MsgAcknowledgement` to Chain A with proof of `0xDEADBEEF`.
4. **Chain A Core**: `AcknowledgePacket` verifies the proof (Success). Calls `transfer.OnAcknowledgementPacket`.
5. **Chain A Transfer**: `OnAcknowledgementPacket` attempts `ModuleCdc.UnmarshalJSON`. Fails. Returns error.
6. **Chain A Core**: Catches error. Reverts execution. **Does not delete packet commitment**.
7. **Result**:
   - `TimeoutPacket` fails: Proof of unreceived/absence fails because the ack *does* exist.
   - `AcknowledgePacket` fails: Always returns error due to parsing.
   - Funds are locked in escrow forever.

### Proof of Concept
A runnable Go test is located in `POC/ibc-ack/ibc_ack_test.go`.

**Command to Run**:
```bash
go test -v ./POC/ibc-ack/
```

**PoC Logic**:
```go
func (suite *PoCTestSuite) TestStuckPacketOnBadAck() {
    // ... setup ...
    // Maliciously set garbage ack on counterparty
    garbageAck := []byte("invalid-json-garbage-ack")
    suite.chainB.GetSimApp().IBCKeeper.ChannelKeeper.SetPacketAcknowledgement(..., garbageAck)

    // Relay Ack to A
    ackMsg := channeltypes.NewMsgAcknowledgement(..., garbageAck, ...)
    res, err := suite.chainA.SendMsgs(ackMsg)

    // Assert Tx Fails
    suite.Require().Error(err)

    // Assert Commitment Remains (Stuck)
    commit := suite.chainA.GetSimApp().IBCKeeper.ChannelKeeper.GetPacketCommitment(...)
    suite.Require().NotEmpty(commit)
}
```

### Remediation
The `transfer` module (and other IBC apps) should handle unmarshal errors in `OnAcknowledgementPacket` by returning `nil` (success/no-op) instead of an error. This allows the core handler to clear the packet commitment, finalizing the lifecycle. While this resolves the local state, the funds are not refunded (as the packet was technically acknowledged), which is the safer "fail-closed" state compared to a permanent lock or a double-spend vulnerability.
