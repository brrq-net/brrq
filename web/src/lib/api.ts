import type {
  Block,
  Transaction,
  Account,
  NetworkStats,
  BlocksResponse,
  TransactionsResponse,
  ValidatorsResponse,
  Validator,
  BridgeStatus,
  EpochInfo,
  LatestProof,
  L1Status,
  BridgeOperator,
  BridgeChallenge,
  GovernanceStats,
  Sequencer,
  HealthStatus,
} from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8545';

async function clientFetchJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

// ── JSON-RPC helper (fallback for endpoints not on REST) ────────

export async function jsonRpc<T>(
  method: string,
  params: unknown[] = []
): Promise<T> {
  const res = await fetch(API_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) {
    throw new Error(`JSON-RPC error ${res.status}: ${res.statusText}`);
  }
  const data = await res.json();
  if (data.error) {
    throw new Error(`JSON-RPC: ${data.error.message ?? JSON.stringify(data.error)}`);
  }
  return data.result as T;
}

// ── Blocks ──────────────────────────────────────────────────────

export async function fetchBlocks(
  page = 1,
  limit = 20
): Promise<BlocksResponse> {
  const offset = (page - 1) * limit;
  return clientFetchJSON<BlocksResponse>(
    `/api/v1/blocks?offset=${offset}&limit=${limit}`
  );
}

export async function fetchBlock(height: number): Promise<Block | null> {
  try {
    return await clientFetchJSON<Block>(`/api/v1/blocks/${height}`);
  } catch {
    return null;
  }
}

export async function fetchRecentBlocks(limit = 5): Promise<Block[]> {
  const res = await clientFetchJSON<BlocksResponse>(
    `/api/v1/blocks?offset=0&limit=${limit}`
  );
  return res.blocks;
}

export async function fetchBlockTransactions(height: number): Promise<Transaction[]> {
  const block = await clientFetchJSON<{ transactions?: Transaction[] }>(`/api/v1/blocks/${height}`);
  return block.transactions ?? [];
}

// ── Transactions ────────────────────────────────────────────────

export async function fetchTransactions(
  page = 1,
  limit = 20
): Promise<TransactionsResponse> {
  const offset = (page - 1) * limit;
  return clientFetchJSON<TransactionsResponse>(
    `/api/v1/transactions?offset=${offset}&limit=${limit}`
  );
}

export async function fetchTransaction(hash: string): Promise<Transaction | null> {
  try {
    return await clientFetchJSON<Transaction>(
      `/api/v1/transactions/${encodeURIComponent(hash)}`
    );
  } catch {
    return null;
  }
}

// ── Accounts ────────────────────────────────────────────────────

export async function fetchAccount(address: string): Promise<Account | null> {
  try {
    return await clientFetchJSON<Account>(
      `/api/v1/accounts/${encodeURIComponent(address)}`
    );
  } catch {
    return null;
  }
}

export async function fetchAccountTransactions(
  address: string,
  page = 1,
  limit = 20
): Promise<{ transactions: Transaction[]; total: number }> {
  const offset = (page - 1) * limit;
  return clientFetchJSON(`/api/v1/accounts/${encodeURIComponent(address)}/transactions?offset=${offset}&limit=${limit}`);
}

// ── Stats & Health ──────────────────────────────────────────────

export async function fetchStats(): Promise<NetworkStats> {
  return clientFetchJSON<NetworkStats>('/api/v1/stats');
}

export async function fetchHealthStatus(): Promise<HealthStatus> {
  return clientFetchJSON<HealthStatus>('/api/v1/health');
}

// ── Validators & Epoch ──────────────────────────────────────────

export async function fetchValidators(): Promise<Validator[]> {
  const res = await clientFetchJSON<ValidatorsResponse>('/api/v1/validators');
  return res.validators;
}

export async function fetchEpochInfo(): Promise<EpochInfo> {
  return clientFetchJSON<EpochInfo>('/api/v1/epoch');
}

// ── Sequencers ──────────────────────────────────────────────────

export async function fetchSequencers(): Promise<Sequencer[]> {
  const res = await clientFetchJSON<{ sequencers: Sequencer[] }>('/api/v1/sequencers');
  return res.sequencers;
}

// ── Bridge ──────────────────────────────────────────────────────

export async function fetchBridgeStatus(): Promise<BridgeStatus> {
  return clientFetchJSON<BridgeStatus>('/api/v1/bridge/status');
}

export async function fetchL1Status(): Promise<L1Status> {
  return clientFetchJSON<L1Status>('/api/v1/l1/status');
}

export async function fetchBridgeOperators(): Promise<BridgeOperator[]> {
  const res = await clientFetchJSON<{ operators: BridgeOperator[] }>('/api/v1/bridge/operators');
  return res.operators;
}

export async function fetchBridgeChallenges(): Promise<BridgeChallenge[]> {
  const res = await clientFetchJSON<{ challenges: BridgeChallenge[] }>('/api/v1/bridge/challenges');
  return res.challenges;
}

// ── Proofs ──────────────────────────────────────────────────────

export async function fetchLatestProof(): Promise<LatestProof | null> {
  try {
    return await clientFetchJSON<LatestProof>('/api/v1/proofs/latest');
  } catch {
    return null;
  }
}

// ── Governance ──────────────────────────────────────────────────

export async function fetchGovernanceStats(): Promise<GovernanceStats> {
  return clientFetchJSON<GovernanceStats>('/api/v1/governance/stats');
}

// ── Portal (L3) ─────────────────────────────────────────────────

export interface PortalLock {
  lock_id: string;
  owner: string;
  amount: number;
  condition_hash: string;
  nullifier_hash: string;
  timeout_l2_block: number;
  status: string;
  created_at_block: number;
}

export interface PortalStats {
  active_locks: number;
  total_escrowed: number;
  nullifiers_consumed: number;
}

export interface NullifierStatus {
  nullifier: string;
  consumed: boolean;
}

export interface PortalSafety {
  lock_id: string;
  nullifier: string;
  safe_to_accept: boolean;
  reason?: string;
}

export async function fetchPortalStats(): Promise<PortalStats> {
  return clientFetchJSON<PortalStats>('/api/v1/portal/stats');
}

export async function fetchPortalLock(lockId: string): Promise<PortalLock | null> {
  try {
    return await clientFetchJSON<PortalLock>(`/api/v1/portal/locks/${lockId}`);
  } catch {
    return null;
  }
}

export async function fetchNullifierStatus(nullifier: string): Promise<NullifierStatus | null> {
  try {
    return await clientFetchJSON<NullifierStatus>(`/api/v1/portal/nullifiers/${nullifier}`);
  } catch {
    return null;
  }
}

export async function fetchPortalSafety(
  lockId: string,
  nullifier: string
): Promise<PortalSafety | null> {
  try {
    return await clientFetchJSON<PortalSafety>(
      `/api/v1/portal/safety/${encodeURIComponent(lockId)}/${encodeURIComponent(nullifier)}`
    );
  } catch {
    return null;
  }
}

// ── Search ──────────────────────────────────────────────────────

export async function search(
  query: string
): Promise<{ type: 'block' | 'transaction' | 'account'; path: string } | null> {
  const trimmed = query.trim();

  if (/^\d+$/.test(trimmed)) {
    const block = await fetchBlock(parseInt(trimmed, 10));
    if (block) {
      return { type: 'block', path: `/blocks/${encodeURIComponent(trimmed)}` };
    }
  }

  if (/^0x[a-fA-F0-9]{64}$/i.test(trimmed)) {
    const tx = await fetchTransaction(trimmed);
    if (tx) {
      return { type: 'transaction', path: `/txs/${encodeURIComponent(trimmed)}` };
    }
  }

  if (/^0x[a-fA-F0-9]{40}$/i.test(trimmed)) {
    const account = await fetchAccount(trimmed);
    if (account) {
      return { type: 'account', path: `/accounts/${encodeURIComponent(trimmed)}` };
    }
  }

  if (trimmed.length >= 20 && !trimmed.startsWith('0x')) {
    const account = await fetchAccount(trimmed);
    if (account) {
      return { type: 'account', path: `/accounts/${encodeURIComponent(trimmed)}` };
    }
  }

  return null;
}
