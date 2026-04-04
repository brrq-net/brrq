'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchBlocks, fetchBlock, fetchRecentBlocks } from '@/lib/api';

export function useBlocks(page = 1, limit = 20) {
  return useQuery({
    queryKey: ['blocks', page, limit],
    queryFn: () => fetchBlocks(page, limit),
    refetchInterval: 10_000,
  });
}

export function useBlock(height: number) {
  return useQuery({
    queryKey: ['block', height],
    queryFn: () => fetchBlock(height),
    enabled: height >= 0,
  });
}

export function useRecentBlocks(limit = 5) {
  return useQuery({
    queryKey: ['recentBlocks', limit],
    queryFn: () => fetchRecentBlocks(limit),
    refetchInterval: 10_000,
  });
}
