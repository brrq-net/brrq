/** Block as returned by GET /api/v1/blocks/{height} and block list items. */
export interface Block {
  height: number;
  hash: string;
  parent_hash: string;
  state_root: string;
  transactions_root: string;
  sequencer: string;
  timestamp: number;
  gas_used: number;
  gas_limit: number;
  tx_count: number;
  epoch: number;
}

/** Transaction as returned by GET /api/v1/transactions/{hash}. */
export interface Transaction {
  hash: string;
  from: string;
  to?: string;
  amount?: number;
  kind: string;
  nonce: number;
  gas_limit: number;
  gas_price: number;
  gas_used?: number;
  block_height: number;
  chain_id?: number;
  success?: boolean;
}

/** Account as returned by GET /api/v1/accounts/{address}. */
export interface Account {
  address: string;
  /** Balance in satoshis — string to avoid JS Number precision loss for large values. */
  balance: string;
  nonce: number;
  code_hash?: string;
  storage_root?: string;
}

/** Network stats as returned by GET /api/v1/stats. */
export interface NetworkStats {
  block_height: number;
  tx_count: number;
  block_count: number;
  validator_count: number;
  /** Total stake in satoshis — string to avoid precision loss. */
  total_stake: string;
  mempool_size: number;
  proof_count: number;
}

/** Validator as returned within GET /api/v1/validators. */
export interface Validator {
  address: string;
  /** Self-stake in satoshis — string to avoid precision loss. */
  stake: string;
  /** Total stake (self + delegated) in satoshis — string to avoid precision loss. */
  total_stake: string;
  status: string;
}

/** Response shape for GET /api/v1/blocks (paginated block list). */
export interface BlocksResponse {
  blocks: Block[];
  total: number;
  limit: number;
  offset: number;
}

/** Response shape for GET /api/v1/transactions (paginated transaction list). */
export interface TransactionsResponse {
  transactions: Transaction[];
  total: number;
  limit: number;
  offset: number;
}

/** Response shape for GET /api/v1/validators. */
export interface ValidatorsResponse {
  validators: Validator[];
}

/** Epoch info as returned by GET /api/v1/epoch. */
export interface EpochInfo {
  current_epoch: number;
  epoch_start_height: number;
  epoch_length: number;
}

/** Bridge status as returned by GET /api/v1/bridge/status. */
export interface BridgeStatus {
  total_locked: string;
  total_minted: string;
  pending_deposits: number;
  pending_withdrawals: number;
  paused: boolean;
}

/** Latest proof as returned by GET /api/v1/proofs/latest. */
export interface LatestProof {
  block_range_start: number;
  block_range_end: number;
  verified: boolean;
}

/** L1 connection status as returned by GET /api/v1/l1/status. */
export interface L1Status {
  connected: boolean;
  l1_height: number;
  network: string;
  anchor_count: number;
  last_anchor_l2_height: number;
}

/** Bridge operator as returned by GET /api/v1/bridge/operators. */
export interface BridgeOperator {
  address: string;
  stake: string;
  status: string;
}

/** Bridge challenge as returned by GET /api/v1/bridge/challenges. */
export interface BridgeChallenge {
  id: string;
  challenger: string;
  challenge_type: string;
  status: string;
  created_at: number;
}

/** Governance stats as returned by GET /api/v1/governance/stats. */
export interface GovernanceStats {
  total_proposals: number;
  active_proposals: number;
  passed_proposals: number;
  rejected_proposals: number;
}

/** Sequencer as returned by GET /api/v1/sequencers. */
export interface Sequencer {
  address: string;
  self_stake: string;
  total_stake: string;
  region: string;
  commission_bp: number;
  status: string;
}

/** Health status as returned by GET /api/v1/health. */
export interface HealthStatus {
  status: string;
  block_height: number;
  epoch: number;
  mempool_size: number;
  l1_connected: boolean;
  active_challenges: number;
  proof_count: number;
}
