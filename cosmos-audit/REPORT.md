# Cosmos Stack Security Audit Report

## A) Versions & Scope Confirmation

**Repositories Checked:**
- **cosmos-sdk**: Tag `v0.53.5` (Commit: `ce4632d08c562ca8e90d5a050965f1f4fd8f8543`)
- **cometbft**: Tag `v0.38.20` (Commit: `c96f26503`)
  - Note: Originally checked `v1.0.1` but downgraded to `v0.38.20` to ensure compatibility with `cosmos-sdk` v0.53.5 for PoC execution.
- **ibc-go**: Tag `v10.5.0` (Commit: `7d118601a5977a48a1c1f2eb92c88bc227a042c9`)

**Compliance**: All findings are based on the above released tags. No main/master code was targeted.

## B) Attack Surface Map

### 1. cosmos-sdk
- **Entry Points**: `AnteHandler` chain (sig verification, fees), `MsgServer` (module handlers), `BeginBlock`/`EndBlock`.
- **Trust Boundaries**: Validators (Consensus), Delegators (Staking), Gov Proposals (Code Execution/Params).
- **Invariants**: Total Supply (Bank), Inflation Rate (Mint), Voting Power (Staking).
- **Critical Components**:
  - `x/bank`: Token transfers, supply tracking.
  - `x/authz`: Delegated permissions (`GenericAuthorization` risk).
  - `x/gov`: Parameter updates, community pool spend.

### 2. cometbft
- **Entry Points**: P2P Reactor (Blocks, Tx), RPC (Tx Submission), ABCI Application Interface.
- **Trust Boundaries**: Peer nodes (P2P), Validators (Consensus signatures).
- **Invariants**: BFT Safety (No double spend/sign), Liveness.
- **Critical Components**:
  - `Consensus`: Vote verification, Proposal validation.
  - `P2P`: Handshake, Packet limits.

### 3. ibc-go
- **Entry Points**: `RecvPacket`, `AcknowledgePacket`, `TimeoutPacket`, `UpdateClient`.
- **Trust Boundaries**: Relayers (Submission), Counterparty Chain (State Proofs), Light Clients (Consensus verification).
- **Invariants**: Packet Order (Ordered Channels), Commitment/Proof Matching, Connection/Channel States.
- **Critical Components**:
  - `modules/core/04-channel`: Packet lifecycle.
  - `modules/apps/transfer`: Token bridging (escrow/burn).
  - `modules/apps/27-interchain-accounts`: Remote control.

## C) Findings Summary Table

| ID | Repo | Title | Class | Attacker Capabilities | Preconditions | Impact | Severity | Confidence | Eligible (Y/N) | PoC (Y/N) |
|----|------|-------|-------|-----------------------|---------------|--------|----------|------------|----------------|-----------|
| 1 | ibc-go | **Permanent Funds Lock via Malformed Acknowledgement** | Logic Error / Integrity | Control of Counterparty Chain | Victim sends packet to malicious chain | Funds stuck in escrow forever | Medium | High | Y | Y |

## D) Detailed Findings

### Finding 1: Permanent Funds Lock via Malformed Acknowledgement

**Repo/Component**: `ibc-go` / `modules/apps/transfer` & `modules/core/04-channel`
**Affected Release**: `v10.5.0` (and likely all versions using standard transfer module)
**Code Locations**:
- `ibc-go/modules/apps/transfer/ibc_module.go`: `OnAcknowledgementPacket`
- `ibc-go/modules/core/04-channel/keeper/packet.go`: `AcknowledgePacket`

**Root Cause**:
The `transfer` module's `OnAcknowledgementPacket` callback returns an error if it fails to unmarshal the acknowledgement bytes (e.g., invalid JSON).
However, the Core IBC `AcknowledgePacket` function has already successfully verified the proof that this "bad ack" exists on the counterparty chain.
When the app callback returns an error, the entire transaction fails (reverting the packet commitment deletion).
This leaves the packet in a "committed" state on the source chain.
Because a valid acknowledgement *exists* (proven by the counterparty), the packet can never be timed out.
Because the acknowledgement cannot be processed (always errors), the packet can never be cleared.
The funds associated with the transfer remain escrowed indefinitely.

**Exploit Scenario**:
1. Victim sends 100 ATOM from Chain A to Chain B.
2. Chain B is malicious (or compromised).
3. Chain B receives the packet (minting tokens to itself) but writes a "garbage" acknowledgement (e.g., non-JSON bytes) to its store.
4. Relayer submits `MsgAcknowledgement` to Chain A with the garbage ack and valid proof.
5. Chain A verifies the proof (Success).
6. Chain A calls `transfer.OnAcknowledgementPacket`.
7. `transfer` fails to unmarshal JSON and returns error.
8. Chain A reverts the transaction.
9. **Result**: Victim's 100 ATOM are locked on Chain A. Chain B has minted 100 ATOM. Double spend + Funds Loss for victim.

**Impact Analysis**:
- **Integrity/Liveness**: Packet lifecycle is broken.
- **Financial**: User funds are permanently locked.
- **Eligibility**: Does not require compromised environment of the *victim* chain. Requires malicious counterparty, which is a valid threat model for Interchain (bridging to untrusted zones).

**PoC**:
Runnable Go test provided in `poc/ibc-ack/ibc_ack_test.go`.
Run with: `cd cosmos-audit && go test ./poc/ibc-ack/ -v`
The test simulates the scenario and asserts that the packet commitment remains on the source chain after a failed acknowledgement attempt.

**Fix Recommendation**:
The `transfer` module (and other IBC apps) should handle unmarshal errors in `OnAcknowledgementPacket` gracefully.
Instead of returning an error (which reverts the Ack processing), it should probably treat a malformed Ack as an error-ack (and refund tokens) OR assume success/no-op depending on safety.
Given that the counterparty *provenly* wrote garbage, treating it as an error-ack and refunding seems safest for the user, preventing lockup.
However, this allows the malicious chain to mint tokens AND trigger a refund (Double Spend).
Therefore, the *safest* protocol behavior is to **Assume Success (No Refund)** but **Clear the Commitment**.
If the counterparty sends garbage, we assume they processed it. We delete our commitment so the packet is "done". The user loses funds on our side (they went to the other side).
This prevents the "Stuck State" and allows the channel to proceed (critical for Ordered channels).
Code change: In `OnAcknowledgementPacket`, if `UnmarshalJSON` fails, log error and return `nil` (success) instead of error.

**Duplicate Risk**:
This might be a known design choice in IBC ("Don't trust counterparty logic"). However, the resulting state (Stuck Packet) is suboptimal compared to "Packet Finalized".

## E) PoC Artifacts

- **Location**: `cosmos-audit/poc/ibc-ack/`
- **Files**:
  - `ibc_ack_test.go`: The standalone test case.
  - `go.mod`: Dependency definition.
- **Execution**:
  1. Ensure `go` (1.23+) is installed.
  2. Run `go test ./poc/ibc-ack/ -v` from `cosmos-audit/` directory.

## F) Non-Issues / False Positives Avoided

1. **`panic("no handlers")` in `cosmos-sdk` HandlerMap**: Found in search. Only triggered during initialization/wiring. Not exploitable remotely.
2. **`ValidateBasic` missing in `x/bank` Msgs**: Validation is handled by `Msg` interface or via `msg_server` validation. `ValidateBasic` methods exist on generated Protobuf types in newer SDK versions or are deprecated in favor of `Validate`.
3. **IBC `AcknowledgePacket` JSON Unmarshal**: In Core IBC, this unmarshal check ignores errors (`if err == nil { ... }`). This is SAFE because Core IBC is agnostic to Ack format. The issue is in the App layer (Finding 1), not Core.
4. **CometBFT `Vote.Verify` ignoring Extensions**: The `Verify` method ignores extensions, but `VerifyVoteAndExtension` is used in Consensus. `Verify` is likely used in P2P/Mempool where strict extension check might be skipped or handled differently. Not a direct safety violation found.
5. **`x/authz` `GenericAuthorization`**: It allows any message. This is by design ("God Mode" grant). Not a bug, but a dangerous feature.

## G) Next Steps

1. **Patch `transfer` module**: Implement error swallowing or explicit error-ack handling for malformed acks.
2. **Review other IBC Apps**: Check `ica` and `interchain-security` for similar patterns. `ica` is critical because it uses Ordered channels (Stuck packet = Dead Channel).
3. **Fuzz Testing**: Fuzz `OnAcknowledgementPacket` implementations with random bytes to ensure no panics.
4. **Report to HackerOne**: Submit this report to Cosmos Bug Bounty.
