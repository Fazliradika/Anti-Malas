# Vulnerability Report: Permanent Funds Lock via Malformed IBC Acknowledgement

**Repo**: `cosmos/ibc-go`
**Component**: `modules/apps/transfer` (ICS-20)
**Affected Versions**: `v10.5.0` (and earlier versions using standard transfer module)
**Severity**: High (Permanent Loss of Funds)

## Summary
A vulnerability in the IBC `transfer` module allows a malicious or malfunctioning counterparty chain to permanently lock user funds on the source chain. By returning a malformed acknowledgement (e.g., non-JSON bytes) for a transfer packet, the counterparty triggers an unmarshalling error in the source chain's `OnAcknowledgementPacket` callback. This error causes the entire acknowledgement transaction to revert, preventing the deletion of the packet commitment. As a result, the packet enters a "stuck" state: it cannot be timed out (because a valid acknowledgement proof exists) and it cannot be successfully acknowledged (because processing always fails).

## Technical Details

### Root Cause
The `OnAcknowledgementPacket` function in `modules/apps/transfer/ibc_module.go` attempts to unmarshal the acknowledgement bytes using `types.ModuleCdc.UnmarshalJSON`.

```go
func (im IBCModule) OnAcknowledgementPacket(...) error {
    var ack channeltypes.Acknowledgement
    if err := types.ModuleCdc.UnmarshalJSON(acknowledgement, &ack); err != nil {
        return errorsmod.Wrapf(ibcerrors.ErrUnknownRequest, "cannot unmarshal ICS-27 transfer packet acknowledgement: %v", err)
    }
    // ...
}
```

In `ibc-go` core (`modules/core/04-channel/keeper/packet.go`), the `AcknowledgePacket` function verifies the proof of the acknowledgement on the counterparty chain. After verification, it calls the application callback:

```go
func (k *Keeper) AcknowledgePacket(...) (string, error) {
    // ... VerifyPacketAcknowledgement (Success) ...

    if err := cbs.OnAcknowledgementPacket(...); err != nil {
        return "", err // Reverts the transaction!
    }

    // k.deletePacketCommitment(...) is NOT reached if error occurs
    return channel.Version, nil
}
```

Because the error from `UnmarshalJSON` propagates up, the deletion of the packet commitment is reverted.

### Exploit Scenario
1. **User Transfer**: A user sends 100 ATOM from Chain A (Source) to Chain B (Dest) via `MsgTransfer`. The 100 ATOM are escrowed on Chain A.
2. **Malicious Processing**: Chain B receives the packet and mints the tokens. However, instead of writing a standard JSON acknowledgement, it writes garbage bytes (e.g., `0xDEADBEEF`) to the packet acknowledgement path.
3. **Relay Attempt**: A Relayer submits `MsgAcknowledgement` to Chain A with the garbage ack and a valid Merkle proof that Chain B committed these bytes.
4. **Verification**: Chain A verifies the proof successfully (the garbage bytes *are* in Chain B's state).
5. **Callback Failure**: Chain A invokes `transfer.OnAcknowledgementPacket`. It fails to unmarshal the garbage bytes and returns an error.
6. **Revert**: The `AcknowledgePacket` transaction on Chain A reverts.
7. **Stuck State**: The packet commitment remains on Chain A. The user cannot request a Timeout because the packet was successfully acknowledged (from the protocol's perspective, proof exists). The user cannot process the Ack because it's malformed. The funds are locked forever.

## Impact
- **Financial Loss**: User funds associated with the packet are permanently locked in the escrow account.
- **Channel Liveness**: For **Ordered** channels (e.g., ICA), this state permanently halts the channel, as the next packet cannot be processed until this one is cleared.

## Recommendation
The `transfer` module (and other IBC applications) should handle unmarshalling errors gracefully. If an acknowledgement cannot be parsed, it should be treated as a "Error Acknowledgement" or a "No-Op", but it **must not return an error** to the core handler if the goal is to finalize the packet lifecycle.

**Proposed Fix**:
Modify `OnAcknowledgementPacket` to log the error and return `nil` (success) when unmarshalling fails. This allows `AcknowledgePacket` to complete, clearing the packet commitment. While this technically means the user loses funds (since they aren't refunded), this is the correct behavior for a finalized packet where the counterparty behaved maliciously. The priority is to clear the local state and prevent the "stuck" scenario.

## Proof of Concept
A runnable Go test case is provided in `POC/ibc-ack/`.

**Steps to Run**:
1. Ensure Go 1.23+ is installed.
2. Navigate to the `POC` directory: `cd POC` (or root).
3. Run the test:
   ```bash
   go test -v ./POC/ibc-ack/
   ```
4. Observe the test passing (verifying the failure condition).

```go
// Excerpt from ibc_ack_test.go
func (suite *PoCTestSuite) TestStuckPacketOnBadAck() {
    // ... Setup channel ...
    // ... Send packet ...
    // ... Maliciously set garbage ack on counterparty ...
    // ... Submit MsgAcknowledgement ...

    // Assert that the transaction fails
    res, err = suite.chainA.SendMsgs(ackMsg)
    suite.Require().Error(err)

    // Assert that the packet commitment STILL exists (Stuck)
    commit := suite.chainA.GetSimApp().IBCKeeper.ChannelKeeper.GetPacketCommitment(...)
    suite.Require().NotEmpty(commit)
}
```
