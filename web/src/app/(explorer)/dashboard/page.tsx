import { StatsCards } from '@/components/dashboard/StatsCards';
import { RecentBlocks } from '@/components/dashboard/RecentBlocks';
import { RecentTxs } from '@/components/dashboard/RecentTxs';

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">Dashboard</h1>
        <p className="text-[var(--text-secondary)]">
          Brrq Bitcoin L2 Network Overview
        </p>
      </div>

      <StatsCards />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentBlocks />
        <RecentTxs />
      </div>
    </div>
  );
}
