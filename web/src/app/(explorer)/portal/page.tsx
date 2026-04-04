'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchPortalStats, fetchPortalLock, fetchNullifierStatus, fetchPortalSafety } from '@/lib/api';
import type { PortalLock, NullifierStatus, PortalSafety } from '@/lib/api';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';

function formatBrqBTC(satoshis: number): string {
  const btc = satoshis / 100_000_000;
  return btc.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }) + ' brqBTC';
}

function formatSats(satoshis: number): string {
  return satoshis.toLocaleString() + ' sats';
}

function statusColor(status: string): string {
  switch (status) {
    case 'Active': return 'text-[var(--electric-green)] bg-[var(--electric-green)]/10 border-[var(--electric-green)]/30';
    case 'Settled': return 'text-[var(--circuit-blue)] bg-[var(--circuit-blue)]/10 border-[var(--circuit-blue)]/30';
    case 'Expired': return 'text-[var(--amber-warning)] bg-[var(--amber-warning)]/10 border-[var(--amber-warning)]/30';
    case 'Cancelled': return 'text-[var(--neon-red)] bg-[var(--neon-red)]/10 border-[var(--neon-red)]/30';
    case 'PendingCancel': return 'text-[var(--amber-warning)] bg-[var(--amber-warning)]/10 border-[var(--amber-warning)]/30';
    case 'PendingSettlement': return 'text-[var(--circuit-blue)] bg-[var(--circuit-blue)]/10 border-[var(--circuit-blue)]/30';
    default: return 'text-[var(--muted-silver)] bg-[var(--gunmetal)]/10 border-[var(--gunmetal)]/30';
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'PendingCancel': return 'Pending Cancel';
    case 'PendingSettlement': return 'Pending Settlement';
    default: return status;
  }
}

export default function PortalPage() {
  const [lockSearch, setLockSearch] = useState('');
  const [nullifierSearch, setNullifierSearch] = useState('');
  const [safetyLockId, setSafetyLockId] = useState('');
  const [safetyNullifier, setSafetyNullifier] = useState('');
  const [searchedLock, setSearchedLock] = useState<PortalLock | null>(null);
  const [searchedNullifier, setSearchedNullifier] = useState<NullifierStatus | null>(null);
  const [safetyResult, setSafetyResult] = useState<PortalSafety | null>(null);
  const [lockError, setLockError] = useState('');
  const [nullifierError, setNullifierError] = useState('');
  const [safetyError, setSafetyError] = useState('');

  const { data: stats, isLoading, isError } = useQuery({
    queryKey: ['portal-stats'],
    queryFn: fetchPortalStats,
    refetchInterval: 10_000,
  });

  const handleLockSearch = async () => {
    if (!lockSearch.trim()) return;
    setLockError('');
    const lock = await fetchPortalLock(lockSearch.trim());
    if (lock) {
      setSearchedLock(lock);
    } else {
      setSearchedLock(null);
      setLockError('Lock not found');
    }
  };

  const handleNullifierSearch = async () => {
    if (!nullifierSearch.trim()) return;
    setNullifierError('');
    const result = await fetchNullifierStatus(nullifierSearch.trim());
    if (result) {
      setSearchedNullifier(result);
    } else {
      setSearchedNullifier(null);
      setNullifierError('Failed to check nullifier');
    }
  };

  const handleSafetyCheck = async () => {
    if (!safetyLockId.trim() || !safetyNullifier.trim()) return;
    setSafetyError('');
    setSafetyResult(null);
    const result = await fetchPortalSafety(safetyLockId.trim(), safetyNullifier.trim());
    if (result) {
      setSafetyResult(result);
    } else {
      setSafetyError('Safety check failed');
    }
  };

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">Portal</h1>
        <p className="text-[var(--text-secondary)]">
          L3 Pragmatic Portal &middot; Account+Escrow with Nullifiers &amp; Batch Settlement
        </p>
      </div>

      {/* API unavailable banner */}
      {isError && (
        <div className="text-center py-8 text-[var(--muted-silver)]">
          Portal API not available. The portal module may not be active on this node.
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Active Locks</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">
            {stats?.active_locks ?? 0}
          </p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Total Escrowed</p>
          <p className="text-2xl font-bold text-[var(--brrq-gold-light)]">
            {stats ? formatBrqBTC(stats.total_escrowed) : '0 brqBTC'}
          </p>
          <p className="text-xs text-[var(--muted-silver)] mt-1">
            {stats ? formatSats(stats.total_escrowed) : '0 sats'}
          </p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Nullifiers Consumed</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">
            {stats?.nullifiers_consumed ?? 0}
          </p>
        </div>
      </div>

      {/* Protocol description */}
      <div className="bg-[var(--obsidian)]/50 cyber-card gold-border p-5">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-3">How Portal Works</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
          <div className="text-center">
            <div className="text-2xl mb-2 text-[var(--brrq-gold-light)]">1</div>
            <p className="text-[var(--text-secondary)] font-medium">Create Lock</p>
            <p className="text-[var(--muted-silver)]">User escrows funds on L2 (single tx)</p>
          </div>
          <div className="text-center">
            <div className="text-2xl mb-2 text-[var(--brrq-gold-light)]">2</div>
            <p className="text-[var(--text-secondary)] font-medium">Generate Key</p>
            <p className="text-[var(--muted-silver)]">Wallet creates Portal Key with Schnorr signature</p>
          </div>
          <div className="text-center">
            <div className="text-2xl mb-2 text-[var(--brrq-gold-light)]">3</div>
            <p className="text-[var(--text-secondary)] font-medium">Instant Verify</p>
            <p className="text-[var(--muted-silver)]">Merchant verifies locally (0.05ms) + checks L2</p>
          </div>
          <div className="text-center">
            <div className="text-2xl mb-2 text-[var(--brrq-gold-light)]">4</div>
            <p className="text-[var(--text-secondary)] font-medium">Batch Settle</p>
            <p className="text-[var(--muted-silver)]">100 settlements in 1 L2 tx (100x compression)</p>
          </div>
        </div>
      </div>

      {/* Lock search */}
      <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-3">Look Up Lock</h2>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Enter lock ID (hex)..."
            value={lockSearch}
            onChange={(e) => setLockSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleLockSearch()}
            className="flex-1 bg-[var(--carbon-black)] border border-[var(--gunmetal)] rounded-lg px-4 py-2 text-[var(--bright-silver)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-[var(--brrq-gold)]"
          />
          <button
            onClick={handleLockSearch}
            className="bg-[var(--brrq-gold)] hover:bg-[var(--brrq-gold-mid)] active:bg-[var(--brrq-gold-dark)] text-[var(--bright-silver)] px-4 py-2 rounded-lg transition-colors"
          >
            Search
          </button>
        </div>
        {lockError && <p className="text-[var(--neon-red)] text-sm mt-2">{lockError}</p>}
        {searchedLock && (
          <div className="mt-4 space-y-2">
            <div className="flex items-center gap-2 mb-3">
              <span className={`px-2 py-0.5 rounded text-xs font-medium border ${statusColor(searchedLock.status)}`}>
                {statusLabel(searchedLock.status)}
              </span>
              {(searchedLock.status === 'PendingCancel' || searchedLock.status === 'PendingSettlement') && (
                <span className="animate-pulse text-xs text-[var(--muted-silver)]">Processing...</span>
              )}
              <span className="text-[var(--muted-silver)] text-sm font-mono">
                {searchedLock.lock_id.slice(0, 16)}...
              </span>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="text-[var(--muted-silver)]">Owner</p>
                <p className="text-[var(--bright-silver)] font-mono text-xs">{searchedLock.owner}</p>
              </div>
              <div>
                <p className="text-[var(--muted-silver)]">Amount</p>
                <p className="text-[var(--brrq-gold-light)] font-bold">{formatBrqBTC(searchedLock.amount)}</p>
              </div>
              <div>
                <p className="text-[var(--muted-silver)]">Timeout Block</p>
                <p className="text-[var(--bright-silver)]">{searchedLock.timeout_l2_block.toLocaleString()}</p>
              </div>
              <div>
                <p className="text-[var(--muted-silver)]">Created At Block</p>
                <p className="text-[var(--bright-silver)]">{searchedLock.created_at_block.toLocaleString()}</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Nullifier check */}
      <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-3">Check Nullifier</h2>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Enter nullifier hash (hex)..."
            value={nullifierSearch}
            onChange={(e) => setNullifierSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleNullifierSearch()}
            className="flex-1 bg-[var(--carbon-black)] border border-[var(--gunmetal)] rounded-lg px-4 py-2 text-[var(--bright-silver)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-[var(--brrq-gold)]"
          />
          <button
            onClick={handleNullifierSearch}
            className="bg-[var(--brrq-gold)] hover:bg-[var(--brrq-gold-mid)] active:bg-[var(--brrq-gold-dark)] text-[var(--bright-silver)] px-4 py-2 rounded-lg transition-colors"
          >
            Check
          </button>
        </div>
        {nullifierError && <p className="text-[var(--neon-red)] text-sm mt-2">{nullifierError}</p>}
        {searchedNullifier && (
          <div className="mt-4 flex items-center gap-3">
            <span className={`px-3 py-1 rounded-lg text-sm font-medium border ${
              searchedNullifier.consumed
                ? 'text-[var(--neon-red)] bg-[var(--neon-red)]/10 border-[var(--neon-red)]/30'
                : 'text-[var(--electric-green)] bg-[var(--electric-green)]/10 border-[var(--electric-green)]/30'
            }`}>
              {searchedNullifier.consumed ? 'Consumed (Spent)' : 'Not Consumed (Available)'}
            </span>
            <span className="text-[var(--muted-silver)] text-xs font-mono">
              {searchedNullifier.nullifier.slice(0, 16)}...
            </span>
          </div>
        )}
      </div>

      {/* Safety check */}
      <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-3">Safety Check</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3">
          Verify if a lock+nullifier pair is safe to accept for payment.
        </p>
        <div className="space-y-2">
          <input
            type="text"
            placeholder="Lock ID (hex)..."
            value={safetyLockId}
            onChange={(e) => setSafetyLockId(e.target.value)}
            className="w-full bg-[var(--carbon-black)] border border-[var(--gunmetal)] rounded-lg px-4 py-2 text-[var(--bright-silver)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-[var(--brrq-gold)]"
          />
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Nullifier hash (hex)..."
              value={safetyNullifier}
              onChange={(e) => setSafetyNullifier(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSafetyCheck()}
              className="flex-1 bg-[var(--carbon-black)] border border-[var(--gunmetal)] rounded-lg px-4 py-2 text-[var(--bright-silver)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-[var(--brrq-gold)]"
            />
            <button
              onClick={handleSafetyCheck}
              className="bg-[var(--brrq-gold)] hover:bg-[var(--brrq-gold-mid)] active:bg-[var(--brrq-gold-dark)] text-[var(--bright-silver)] px-4 py-2 rounded-lg transition-colors"
            >
              Verify
            </button>
          </div>
        </div>
        {safetyError && <p className="text-[var(--neon-red)] text-sm mt-2">{safetyError}</p>}
        {safetyResult && (
          <div className="mt-4">
            <span className={`px-3 py-1 rounded-lg text-sm font-medium border ${
              safetyResult.safe_to_accept
                ? 'text-[var(--electric-green)] bg-[var(--electric-green)]/10 border-[var(--electric-green)]/30'
                : 'text-[var(--neon-red)] bg-[var(--neon-red)]/10 border-[var(--neon-red)]/30'
            }`}>
              {safetyResult.safe_to_accept ? 'Safe to Accept' : 'Not Safe'}
            </span>
            {safetyResult.reason && (
              <p className="text-sm text-[var(--text-secondary)] mt-2">{safetyResult.reason}</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
