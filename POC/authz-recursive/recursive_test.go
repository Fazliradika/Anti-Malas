package authz_recursive_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	"github.com/cosmos/cosmos-sdk/x/authz"
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	authzmodule "github.com/cosmos/cosmos-sdk/x/authz/module"
	authztestutil "github.com/cosmos/cosmos-sdk/x/authz/testutil"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

type TestSuite struct {
	suite.Suite

	ctx           sdk.Context
	addrs         []sdk.AccAddress
	authzKeeper   authzkeeper.Keeper
	accountKeeper *authztestutil.MockAccountKeeper
	bankKeeper    *authztestutil.MockBankKeeper
	baseApp       *baseapp.BaseApp
	encCfg        moduletestutil.TestEncodingConfig
}

func (s *TestSuite) SetupTest() {
	key := storetypes.NewKVStoreKey(authzkeeper.StoreKey)
	storeService := runtime.NewKVStoreService(key)
	testCtx := testutil.DefaultContextWithDB(s.T(), key, storetypes.NewTransientStoreKey("transient_test"))
	s.ctx = testCtx.Ctx.WithBlockHeader(cmtproto.Header{Time: cmttime.Now()})
	s.encCfg = moduletestutil.MakeTestEncodingConfig(authzmodule.AppModuleBasic{})

	s.baseApp = baseapp.NewBaseApp(
		"authz",
		log.NewNopLogger(),
		testCtx.DB,
		s.encCfg.TxConfig.TxDecoder(),
	)
	s.baseApp.SetCMS(testCtx.CMS)
	s.baseApp.SetInterfaceRegistry(s.encCfg.InterfaceRegistry)

	s.addrs = simtestutil.CreateIncrementalAccounts(7)

	ctrl := gomock.NewController(s.T())
	s.accountKeeper = authztestutil.NewMockAccountKeeper(ctrl)
	s.accountKeeper.EXPECT().AddressCodec().Return(address.NewBech32Codec("cosmos")).AnyTimes()

	s.bankKeeper = authztestutil.NewMockBankKeeper(ctrl)
	banktypes.RegisterInterfaces(s.encCfg.InterfaceRegistry)
	banktypes.RegisterMsgServer(s.baseApp.MsgServiceRouter(), s.bankKeeper)
	s.bankKeeper.EXPECT().BlockedAddr(gomock.Any()).Return(false).AnyTimes()

	s.authzKeeper = authzkeeper.NewKeeper(storeService, s.encCfg.Codec, s.baseApp.MsgServiceRouter(), s.accountKeeper).SetBankKeeper(s.bankKeeper)

	// Register Authz MsgServer
	authz.RegisterMsgServer(s.baseApp.MsgServiceRouter(), s.authzKeeper)
}

func (s *TestSuite) TestRecursiveMsgExec() {
	require := s.Require()
	granter := s.addrs[0]
	grantee := s.addrs[1]

	// 1. Grant GenericAuthorization for MsgExec itself!
	// This allows grantee to execute MsgExec on behalf of granter.
	// Since MsgExec is what we are executing, we are essentially allowing recursion.
	msgExecType := sdk.MsgTypeURL(&authz.MsgExec{})
	genAuth := authz.NewGenericAuthorization(msgExecType)
	expiration := s.ctx.BlockTime().Add(1 * time.Hour)

	err := s.authzKeeper.SaveGrant(s.ctx, grantee, granter, genAuth, &expiration)
	require.NoError(err)

	// 2. Construct deeply nested MsgExec
	// Level 0: MsgExec(MsgSend)
	// Level 1: MsgExec(MsgExec(MsgSend))
	// ...

	depth := 2000 // Try a depth that might cause stack overflow if unchecked

	// Base message
	baseMsg := &banktypes.MsgSend{
		FromAddress: granter.String(),
		ToAddress:   grantee.String(),
		Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 1)),
	}

	currentMsg := sdk.Msg(baseMsg)

	for i := 0; i < depth; i++ {
		// Wrap with MsgExec
		// MsgExec(grantee, []Msg{currentMsg})
		// When executed, the handler sees the outer MsgExec signed by `grantee` (or whoever sends the tx).
		// But wait, MsgExec executes `Msgs` on behalf of `Grantee` (field in MsgExec)?
		// No, `MsgExec` struct has `Grantee` field. This is the account that HAS the grant.
		// The `Signer` of MsgExec is the one who submits it (the grantee).
		// Inside `Exec`: `DispatchActions(ctx, msg.Grantee, msgs)`
		// It checks if `Signer` (granter of execution) matches `msg.Grantee`.

		// In recursion:
		// Outer: NewMsgExec(grantee, [Inner])
		// Inner: NewMsgExec(grantee, [Base])
		// All MsgExecs use the SAME grantee, effectively re-using the same grant?
		// Yes, if A grants B, B can execute "A grants B...".

		// Wait, if I am B, and I send `MsgExec(Grantee=B, Msgs=[MsgExec(Grantee=B, Msgs=[MsgSend])])`
		// 1. Outer Exec: `DispatchActions` for B. Signer is B. B==B.
		//    It iterates Msgs. First msg is `MsgExec`.
		//    `router.Handler(MsgExec)` is called.
		//    `Exec(MsgExec)` is called.
		// 2. Inner Exec: `MsgExec` has Grantee=B.
		//    `DispatchActions` for B. Signer is B (propagated? No, internal dispatch doesn't change signer context usually, but `Exec` derives signer from the Msg).
		//    In `DispatchActions`, `Signers` are retrieved from the msg.
		//    Inner MsgExec signer is B.
		//    So B executes MsgExec on behalf of B?
		//    If B==B, no authz check needed! "If granter != grantee then check authorization... otherwise implicitly accept."

		// So I don't even need a Grant if I execute on behalf of myself!
		// `MsgExec` allows executing on behalf of self?
		// `NewMsgExec(grantee, ...)`
		// `Exec` checks `msg.Grantee`.
		// `GetMsgV1Signers` of `MsgExec` returns `Grantee`.
		// So `Signer` is `Grantee`.
		// If I send a Tx signed by B, containing `MsgExec(Grantee=B, ...)`, then `Exec` sees Signer=B, Grantee=B.
		// `DispatchActions` checks `granter` (signer of msg) vs `grantee` (arg).
		// Wait, `DispatchActions(ctx, grantee, msgs)`.
		// Inside loop: `signers = msg.GetSigners()`. `granter = signers[0]`.
		// `if !bytes.Equal(granter, grantee)` -> Check Grant.
		// If `granter == grantee`, Implicitly Accept.

		// So if I construct `MsgExec(Grantee=B, Msgs=[MsgExec(Grantee=B, Msgs=[...])])`
		// Each level, `granter` (signer of inner msg) is `B`. `grantee` (context) is `B`.
		// So it recurses without grants.

		// So I don't need the grant step!

		execMsg := authz.NewMsgExec(grantee, []sdk.Msg{currentMsg})
		currentMsg = &execMsg
	}

	// 3. Execute
	// We need to wrap the top-level MsgExec in a Transaction or just call the handler directly?
	// `s.msgSrvr.Exec` calls the handler.

	topMsg, ok := currentMsg.(*authz.MsgExec)
	require.True(ok)

	// Verify if it can be Marshaled/Unmarshaled (Wire Check)
	s.T().Logf("Marshaling nested message...")
	bz, err := s.encCfg.Codec.MarshalInterface(topMsg)
	require.NoError(err)

	s.T().Logf("Unmarshaling nested message...")
	var decodedMsg sdk.Msg
	err = s.encCfg.Codec.UnmarshalInterface(bz, &decodedMsg)
	require.NoError(err, "Unmarshal should pass if no recursion limit")

	s.T().Logf("Executing recursive MsgExec with depth %d", depth)

	// This should panic with stack overflow if unchecked
	_, err = s.authzKeeper.Exec(s.ctx, topMsg)
	require.NoError(err)
}

func TestTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
