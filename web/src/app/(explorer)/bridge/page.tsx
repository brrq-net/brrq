'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchBridgeStatus, fetchStats } from '@/lib/api';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';

function formatBTC(satoshis: string | number): string {
  const n = typeof satoshis === 'string' ? Number(satoshis) : satoshis;
  if (!Number.isFinite(n)) return typeof satoshis === 'string' ? `${satoshis} sats` : '0 BTC';
  const btc = n / 100_000_000;
  return btc.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }) + ' BTC';
}

function formatBrqBTC(satoshis: string | number): string {
  const n = typeof satoshis === 'string' ? Number(satoshis) : satoshis;
  if (!Number.isFinite(n)) return typeof satoshis === 'string' ? `${satoshis} sats` : '0 brqBTC';
  const btc = n / 100_000_000;
  return btc.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }) + ' brqBTC';
}

export default function BridgePage() {
  const { data: bridge, isLoading, error } = useQuery({
    queryKey: ['bridge-status'],
    queryFn: fetchBridgeStatus,
    refetchInterval: 15_000,
  });

  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    refetchInterval: 15_000,
  });

  if (isLoading) return <LoadingSpinner />;

  const hasBridge = !error && bridge;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">Bridge</h1>
        <p className="text-[var(--text-secondary)]">
          BTC &harr; brqBTC &middot; BitVM2 trustless bridge
        </p>
      </div>

      {/* Status banner */}
      {hasBridge && bridge.paused && (
        <div className="bg-[var(--neon-red)]/10 border border-[var(--neon-red)]/30 cyber-card p-4 text-[var(--neon-red)]">
          Bridge is currently paused. Deposits and withdrawals are temporarily disabled.
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Total Locked (L1)</p>
          <p className="text-2xl font-bold text-[var(--brrq-gold-light)]">
            {hasBridge ? formatBTC(bridge.total_locked) : '\u2014'}
          </p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Total Minted (L2)</p>
          <p className="text-2xl font-bold text-[var(--circuit-blue)]">
            {hasBridge ? formatBrqBTC(bridge.total_minted) : '\u2014'}
          </p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Pending Deposits</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">
            {hasBridge ? bridge.pending_deposits : '\u2014'}
          </p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Pending Withdrawals</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">
            {hasBridge ? bridge.pending_withdrawals : '\u2014'}
          </p>
        </div>
      </div>

      {/* Bridge info */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Peg-in */}
        <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow p-6">
          <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-1">
            Peg-In (BTC &rarr; brqBTC)
          </h2>
          <p className="text-xs text-[var(--muted-silver)] mb-4">Design Specification (planned)</p>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Fee</span>
              <span className="text-[var(--bright-silver)]">0.05%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Confirmations Required</span>
              <span className="text-[var(--bright-silver)]">6 blocks (~60 min)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Min Deposit</span>
              <span className="text-[var(--bright-silver)]">0.001 BTC</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Max Deposit</span>
              <span className="text-[var(--bright-silver)]">10 BTC</span>
            </div>
          </div>
        </div>

        {/* Peg-out */}
        <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow p-6">
          <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-1">
            Peg-Out (brqBTC &rarr; BTC)
          </h2>
          <p className="text-xs text-[var(--muted-silver)] mb-4">Design Specification (planned)</p>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Fee</span>
              <span className="text-[var(--bright-silver)]">0.1%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Challenge Period</span>
              <span className="text-[var(--bright-silver)]">2016 blocks (~2 weeks)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Verification</span>
              <span className="text-[var(--bright-silver)]">STARK Proof (BitVM2)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Federation</span>
              <span className="text-[var(--bright-silver)]">5-of-9 Multisig (fallback)</span>
            </div>
          </div>
        </div>
      </div>

      {/* STARK Proofs */}
      <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow p-6">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-4">STARK Proofs</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <p className="text-sm text-[var(--text-secondary)]">Total Proofs Generated</p>
            <p className="text-xl font-bold text-[var(--text-primary)] mt-1">
              {stats?.proof_count ?? '\u2014'}
            </p>
          </div>
          <div>
            <p className="text-sm text-[var(--text-secondary)]">Proof System</p>
            <p className="text-xl font-bold text-[var(--text-primary)] mt-1">STARK + Plonky2</p>
          </div>
          <div>
            <p className="text-sm text-[var(--text-secondary)]">On-Chain Proof Size</p>
            <p className="text-xl font-bold text-[var(--text-primary)] mt-1">~200 KB (STARK)</p>
          </div>
        </div>
      </div>

      {!hasBridge && (
        <div className="text-center py-8 text-[var(--muted-silver)]">
          Bridge status API not available. The bridge module may not be active on this node.
        </div>
      )}
    </div>
  );
}
