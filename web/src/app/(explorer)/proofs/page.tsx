'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchLatestProof, fetchStats } from '@/lib/api';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';

export default function ProofsPage() {
  const { data: proof, isLoading } = useQuery({
    queryKey: ['latest-proof'],
    queryFn: fetchLatestProof,
    refetchInterval: 30_000,
  });

  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    refetchInterval: 10_000,
  });

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">STARK Proofs</h1>
        <p className="text-[var(--text-secondary)]">Zero-knowledge proof verification status</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Total Proofs</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">{stats?.proof_count ?? 0}</p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Proof System</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">STARK + Plonky2</p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-5">
          <p className="text-sm text-[var(--text-secondary)] mb-1">Field</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">BabyBear</p>
        </div>
      </div>

      {proof ? (
        <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow p-6">
          <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Latest Proof</h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-[var(--text-secondary)]">Block Range</span>
              <span className="text-[var(--bright-silver)]">#{proof.block_range_start} — #{proof.block_range_end}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-[var(--text-secondary)]">Blocks Covered</span>
              <span className="text-[var(--bright-silver)]">{proof.block_range_end - proof.block_range_start + 1}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-[var(--text-secondary)]">Verified</span>
              <span className={proof.verified ? 'text-[var(--electric-green)]' : 'text-[var(--amber-warning)]'}>
                {proof.verified ? 'Yes' : 'Pending'}
              </span>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-8 text-center text-[var(--text-secondary)]">
          No proofs generated yet.
        </div>
      )}

      <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow p-6">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Architecture</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">VM</span>
              <span className="text-[var(--bright-silver)]">RISC-V (RV32IM)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Hash Function</span>
              <span className="text-[var(--bright-silver)]">Poseidon2</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">FRI Commitments</span>
              <span className="text-[var(--bright-silver)]">Poseidon2</span>
            </div>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Wrapper</span>
              <span className="text-[var(--bright-silver)]">Plonky2 (transparent)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Trusted Setup</span>
              <span className="text-[var(--bright-silver)]">None required</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">Post-Quantum</span>
              <span className="text-[var(--bright-silver)]">Hash-based (safe)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
