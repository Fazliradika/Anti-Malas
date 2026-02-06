module poc/authz-recursive

go 1.24

require (
	cosmossdk.io/log v1.6.1
	cosmossdk.io/store v1.1.2
	github.com/cometbft/cometbft v0.38.20
	github.com/cosmos/cosmos-sdk v0.53.5
	github.com/stretchr/testify v1.11.1
	go.uber.org/mock v0.6.0
)

replace (
	github.com/cosmos/cosmos-sdk => ../../cosmos-sdk
	github.com/cometbft/cometbft => ../../cometbft
)
