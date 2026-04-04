import { ExternalLink } from 'lucide-react';

const links = [
  { label: 'GitHub', href: 'https://github.com/brrq-net/brrq' },
  { label: 'Docs', href: '/docs' },
  { label: 'X', href: 'https://x.com/BrrqNetwork' },
];

export function Footer() {
  return (
    <footer className="border-t border-[var(--gunmetal)] py-6 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex flex-col sm:flex-row items-center gap-2">
            <p className="text-sm text-[var(--muted-silver)]">
              Powered by{' '}
              <span className="text-[var(--brrq-gold-light)] font-semibold">Brrq</span>
              {' '}&mdash; Bitcoin L2 with Hash-First Architecture
            </p>
            <span className="text-xs text-[var(--gunmetal)] hidden sm:inline">&middot;</span>
            <p className="text-xs text-[var(--muted-silver)]">&copy; 2025-2026 Brrq Protocol</p>
          </div>
          <div className="flex items-center gap-4 text-sm">
            {links.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="text-[var(--muted-silver)] hover:text-[var(--brrq-gold-light)] transition-colors flex items-center gap-1"
                {...(link.href.startsWith('http')
                  ? { target: '_blank', rel: 'noopener noreferrer' }
                  : {})}
              >
                {link.label}
                {link.href.startsWith('http') && (
                  <ExternalLink className="h-3 w-3" />
                )}
              </a>
            ))}
            <span className="text-[var(--gunmetal)]">|</span>
            <span className="text-[var(--muted-silver)]">SLH-DSA</span>
            <span className="text-[var(--gunmetal)]">|</span>
            <span className="text-[var(--muted-silver)]">ZK-STARK</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
