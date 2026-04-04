'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Search } from 'lucide-react';
import { search } from '@/lib/api';

interface SearchBarProps {
  className?: string;
  compact?: boolean;
}

export function SearchBar({ className = '', compact = false }: SearchBarProps) {
  const [query, setQuery] = useState('');
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState('');
  const router = useRouter();

  const handleSearch = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = query.trim();
      if (!trimmed) return;

      setSearching(true);
      setError('');

      try {
        const result = await search(trimmed);
        if (result) {
          router.push(result.path);
          setQuery('');
        } else {
          setError('No results found');
          setTimeout(() => setError(''), 3000);
        }
      } catch {
        setError('Search failed');
        setTimeout(() => setError(''), 3000);
      } finally {
        setSearching(false);
      }
    },
    [query, router]
  );

  return (
    <form onSubmit={handleSearch} className={`relative ${className}`}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted-silver)]" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder=""
          className={`w-full bg-[var(--carbon-black)] border border-[var(--gunmetal)] rounded-lg pl-10 pr-4 text-sm text-[var(--bright-silver)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-[var(--brrq-gold)] focus:ring-1 focus:ring-[var(--brrq-gold)] ${
            compact ? 'py-1.5' : 'py-2.5'
          } ${error ? 'border-[var(--neon-red)]' : ''}`}
          disabled={searching}
        />
        {searching && (
          <div className="absolute right-3 top-1/2 -translate-y-1/2">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-[var(--gunmetal)] border-t-[var(--brrq-gold)]" />
          </div>
        )}
      </div>
      {error && (
        <p className="absolute top-full left-0 mt-1 text-xs text-[var(--neon-red)]">{error}</p>
      )}
    </form>
  );
}
