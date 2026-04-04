'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchAccount } from '@/lib/api';

export function useAccount(address: string) {
  return useQuery({
    queryKey: ['account', address],
    queryFn: () => fetchAccount(address),
    enabled: !!address,
  });
}
