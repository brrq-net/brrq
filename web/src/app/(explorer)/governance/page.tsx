'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchGovernanceStats } from '@/lib/api';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';

export default function GovernancePage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['governance-stats'],
    queryFn: fetchGovernanceStats,
    refetchInterval: 15_000,
  });

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">Governance</h1>
        <p className="text-[var(--text-secondary)]">On-chain governance overview</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-4">
          <p className="text-sm text-[var(--text-secondary)]">Total Proposals</p>
          <p className="text-2xl font-bold text-[var(--text-primary)] mt-1">{stats?.total_proposals ?? 0}</p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-4">
          <p className="text-sm text-[var(--text-secondary)]">Active</p>
          <p className="text-2xl font-bold text-[var(--circuit-blue)] mt-1">{stats?.active_proposals ?? 0}</p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-4">
          <p className="text-sm text-[var(--text-secondary)]">Passed</p>
          <p className="text-2xl font-bold text-[var(--electric-green)] mt-1">{stats?.passed_proposals ?? 0}</p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-4">
          <p className="text-sm text-[var(--text-secondary)]">Rejected</p>
          <p className="text-2xl font-bold text-[var(--neon-red)] mt-1">{stats?.rejected_proposals ?? 0}</p>
        </div>
      </div>

      <div className="bg-[var(--obsidian)] cyber-card gold-border p-8 text-center text-[var(--text-secondary)]">
        <p>Governance proposals are managed on-chain.</p>
        <p className="text-sm text-[var(--muted-silver)] mt-2">
          The /governance/proposals endpoint is not available on this node.
          Stats are shown above from /governance/stats.
        </p>
      </div>
    </div>
  );
}
