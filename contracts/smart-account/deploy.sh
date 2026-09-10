#!/usr/bin/env bash
set -euo pipefail

# Deploy all Credis smart contracts to the given environment.
# Usage: ./deploy.sh [env_name] [deploy_mock_token]
#   env_name           defaults to "local-reth"
#   deploy_mock_token  "true" or "false". Defaults to "true" when env_name starts with "local",
#                      otherwise defaults to "false".
#
# The Solidity scripts append `export VAR=0x...` lines to $DEPLOYMENT_ENV_FILE.
# That path is exported so BaseScript.deploymentFilePath() writes to the same
# file the shell sources from, regardless of which chain id the RPC reports.

ENV_NAME="${1:-local-reth}"

if [[ "$ENV_NAME" == local* ]]; then
  DEFAULT_DEPLOY_MOCK_TOKEN="true"
else
  DEFAULT_DEPLOY_MOCK_TOKEN="false"
fi
DEPLOY_MOCK_TOKEN="${2:-$DEFAULT_DEPLOY_MOCK_TOKEN}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.${ENV_NAME}.env"
export DEPLOYMENT_ENV_FILE="$SCRIPT_DIR/.${ENV_NAME}.deployment.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Error: $ENV_FILE not found"
  exit 1
fi

echo "=== Using environment: $ENV_NAME ==="
echo "=== Deploy mock token: $DEPLOY_MOCK_TOKEN ==="
source "$ENV_FILE"

# Reset the deployment file so a fresh run does not concatenate stale entries
# under the new run's `# ... deployment at block N timestamp T` header.
: > "$DEPLOYMENT_ENV_FILE"

FORGE_COMMON_FLAGS="--rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvv"

if [[ "$DEPLOY_MOCK_TOKEN" == "true" ]]; then
  echo "=== Step 1: Deploy MockToken ==="
  forge script script/DeployMockToken.s.sol $FORGE_COMMON_FLAGS

  source "$DEPLOYMENT_ENV_FILE"

  echo ""
  echo "ERC20: ${ERC20_ADDRESS:-<unset>}"
else
  echo "=== Step 1: Skipping MockToken deployment ==="
  echo ""
  echo "Using ERC20: ${ERC20_ADDRESS:-<unset>}"
fi

echo ""
echo "=== Step 2: Deploy Kernel Stack ==="
forge script script/DeployKernelStack.s.sol $FORGE_COMMON_FLAGS

source "$DEPLOYMENT_ENV_FILE"

echo ""
echo "EntryPoint:          ${ENTRYPOINT_ADDRESS:-<unset>}"
echo "KernelUUPS:          ${KERNEL_UUPS_ADDRESS:-<unset>}"
echo "KernelImmutableECDSA:${KERNEL_IMMUTABLE_ECDSA_ADDRESS:-<unset>}"
echo "KernelFactory:       ${KERNEL_FACTORY_ADDRESS:-<unset>}"
echo "CallerHook:          ${CALLER_HOOK_ADDRESS:-<unset>}"
echo "ECDSASigner:         ${ECDSA_SIGNER_ADDRESS:-<unset>}"

echo ""
echo "=== Step 3: Deploy Smart Account Stack ==="
forge script script/DeploySmartAccountStack.s.sol $FORGE_COMMON_FLAGS

source "$DEPLOYMENT_ENV_FILE"

echo ""
echo "BundleModulePlugin:        ${BUNDLE_MODULE_PLUGIN_ADDRESS:-<unset>}"
echo "WithdrawalLimitPolicy:     ${WITHDRAWAL_LIMIT_POLICY_ADDRESS:-<unset>}"
echo "BundleSpendProtectorHook:  ${BUNDLE_SPEND_PROTECTOR_HOOK_ADDRESS:-<unset>}"
echo "BundleWithdrawHook:        ${BUNDLE_WITHDRAW_HOOK_ADDRESS:-<unset>}"
echo "SudoPolicy:                ${SUDO_POLICY_ADDRESS:-<unset>}"
echo "SmartAccountFactory:       ${SMART_ACCOUNT_FACTORY_ADDRESS:-<unset>}"

echo ""
echo "=== Deployment complete ==="
echo "All addresses written to $DEPLOYMENT_ENV_FILE"
