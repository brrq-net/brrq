'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchSequencers } from '@/lib/api';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { HashLink } from '@/components/ui/HashLink';
import { formatSats } from '@/lib/utils';

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    active: 'bg-[var(--electric-green)]/20 text-[var(--electric-green)] border-[var(--electric-green)]/30',
    pending: 'bg-[var(--amber-warning)]/20 text-[var(--amber-warning)] border-[var(--amber-warning)]/30',
    inactive: 'bg-[var(--gunmetal)]/20 text-[var(--muted-silver)] border-[var(--gunmetal)]/30',
  };
  const color = colors[status.toLowerCase()] || colors.inactive;
  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${color}`}>
      {status}
    </span>
  );
}

export default function SequencersPage() {
  const { data: sequencers, isLoading } = useQuery({
    queryKey: ['sequencers'],
    queryFn: fetchSequencers,
    refetchInterval: 10_000,
  });

  if (isLoading) return <LoadingSpinner />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">Sequencers</h1>
        <p className="text-[var(--text-secondary)]">
          {sequencers?.length ?? 0} registered sequencers
        </p>
      </div>

      <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--gunmetal)] text-[var(--text-secondary)] bg-[var(--graphite)]">
                <th className="px-4 py-3 text-left font-medium">#</th>
                <th className="px-4 py-3 text-left font-medium">Address</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3 text-left font-medium">Region</th>
                <th className="px-4 py-3 text-right font-medium">Self Stake</th>
                <th className="px-4 py-3 text-right font-medium">Total Stake</th>
                <th className="px-4 py-3 text-right font-medium">Commission</th>
              </tr>
            </thead>
            <tbody>
              {sequencers?.map((s, i) => (
                <tr key={s.address} className="border-b border-[var(--gunmetal)]/50 hover:bg-[var(--dark-steel)]/30 transition-colors">
                  <td className="px-4 py-3 text-[var(--muted-silver)]">{i + 1}</td>
                  <td className="px-4 py-3"><HashLink hash={s.address} type="account" /></td>
                  <td className="px-4 py-3">{statusBadge(s.status)}</td>
                  <td className="px-4 py-3 text-[var(--text-secondary)]">{s.region}</td>
                  <td className="px-4 py-3 text-right text-[var(--bright-silver)] font-mono">{formatSats(s.self_stake)}</td>
                  <td className="px-4 py-3 text-right text-[var(--bright-silver)] font-mono">{formatSats(s.total_stake)}</td>
                  <td className="px-4 py-3 text-right text-[var(--text-secondary)]">{(s.commission_bp / 100).toFixed(2)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(!sequencers || sequencers.length === 0) && (
          <div className="text-center py-12 text-[var(--text-secondary)]">No sequencers registered yet.</div>
        )}
      </div>
    </div>
  );
}
