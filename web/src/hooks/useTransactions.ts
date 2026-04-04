'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchTransaction } from '@/lib/api';

/** Fetch a single transaction by hash. */
export function useTransaction(hash: string) {
  return useQuery({
    queryKey: ['transaction', hash],
    queryFn: () => fetchTransaction(hash),
    enabled: !!hash,
  });
}
