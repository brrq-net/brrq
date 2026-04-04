'use client';

import { Blocks, ArrowRightLeft, Users, ShieldCheck } from 'lucide-react';
import { useStats } from '@/hooks/useStats';
import { formatNumber } from '@/lib/utils';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';

interface StatCardProps {
  title: string;
  value: string;
  icon: React.ReactNode;
  subtitle?: string;
}

function StatCard({ title, value, icon, subtitle }: StatCardProps) {
  return (
    <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow p-5 gold-glow-hover transition-all">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-[var(--text-secondary)] mb-1">{title}</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">{value}</p>
          {subtitle && (
            <p className="text-xs text-[var(--muted-silver)] mt-1">{subtitle}</p>
          )}
        </div>
        <div className="bg-[var(--brrq-gold)]/10 rounded-lg p-2.5 text-[var(--brrq-gold-light)]">
          {icon}
        </div>
      </div>
    </div>
  );
}

export function StatsCards() {
  const { data: stats, isLoading, isError } = useStats();

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="bg-[var(--obsidian)] cyber-card gold-border p-5 h-[108px] flex items-center justify-center"
          >
            <LoadingSpinner size="sm" />
          </div>
        ))}
      </div>
    );
  }

  if (isError || !stats) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Block Height"
          value="--"
          icon={<Blocks className="h-5 w-5" />}
        />
        <StatCard
          title="Transactions"
          value="--"
          icon={<ArrowRightLeft className="h-5 w-5" />}
        />
        <StatCard
          title="Validators"
          value="--"
          icon={<Users className="h-5 w-5" />}
        />
        <StatCard
          title="Proofs"
          value="--"
          icon={<ShieldCheck className="h-5 w-5" />}
        />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        title="Block Height"
        value={formatNumber(stats.block_height)}
        icon={<Blocks className="h-5 w-5" />}
        subtitle={`${formatNumber(stats.block_count)} blocks`}
      />
      <StatCard
        title="Transactions"
        value={formatNumber(stats.tx_count)}
        icon={<ArrowRightLeft className="h-5 w-5" />}
        subtitle={`${formatNumber(stats.mempool_size)} in mempool`}
      />
      <StatCard
        title="Validators"
        value={formatNumber(stats.validator_count)}
        icon={<Users className="h-5 w-5" />}
        subtitle={`${formatNumber(Number(stats.total_stake))} total stake`}
      />
      <StatCard
        title="STARK Proofs"
        value={formatNumber(stats.proof_count)}
        icon={<ShieldCheck className="h-5 w-5" />}
      />
    </div>
  );
}
