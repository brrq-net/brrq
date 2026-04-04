import Link from 'next/link';
import { shortenHash } from '@/lib/utils';

interface HashLinkProps {
  hash: string;
  type: 'block' | 'tx' | 'account';
  shorten?: boolean;
  prefixLen?: number;
  suffixLen?: number;
  className?: string;
}

function getHref(type: string, hash: string): string {
  switch (type) {
    case 'block':
      return `/blocks/${hash}`;
    case 'tx':
      return `/txs/${hash}`;
    case 'account':
      return `/accounts/${hash}`;
    default:
      return '#';
  }
}

export function HashLink({
  hash,
  type,
  shorten = true,
  prefixLen = 10,
  suffixLen = 6,
  className = '',
}: HashLinkProps) {
  const displayHash = shorten ? shortenHash(hash, prefixLen, suffixLen) : hash;

  return (
    <Link
      href={getHref(type, hash)}
      className={`font-mono text-[var(--brrq-gold-light)] hover:text-[var(--brrq-gold)] hover:underline ${className}`}
      title={hash}
    >
      {displayHash}
    </Link>
  );
}
