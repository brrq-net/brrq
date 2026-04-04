'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import Image from 'next/image';
import { Menu, X } from 'lucide-react';
import { useState } from 'react';
import { SearchBar } from '@/components/ui/SearchBar';
import { ThemeToggle } from '@/components/ui/ThemeToggle';

const navLinks = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/blocks', label: 'Blocks' },
  { href: '/txs', label: 'Transactions' },
  { href: '/validators', label: 'Validators' },
  { href: '/sequencers', label: 'Sequencers' },
  { href: '/bridge', label: 'Bridge' },
  { href: '/proofs', label: 'Proofs' },
  { href: '/governance', label: 'Governance' },
  { href: '/portal', label: 'Portal' },
  { href: '/docs', label: 'Docs' },
];

export function Header() {
  const pathname = usePathname();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  function isActive(href: string): boolean {
    if (href === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(href);
  }

  return (
    <header className="bg-[var(--void-black)]/80 backdrop-blur-sm border-b border-[var(--gunmetal)] sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 shrink-0">
            <Image src="/logo.png" alt="Brrq" width={36} height={36} className="rounded" />
            <div className="flex items-baseline gap-1.5">
              <span className="text-lg font-bold text-[var(--bright-silver)]">Brrq</span>
              <span className="text-xs text-[var(--text-secondary)] hidden sm:inline">Explorer</span>
            </div>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden lg:flex items-center gap-1 ml-6">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={`px-2.5 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive(link.href)
                    ? 'bg-[var(--dark-steel)] text-[var(--brrq-gold-light)]'
                    : 'text-[var(--text-secondary)] hover:text-[var(--bright-silver)] hover:bg-[var(--dark-steel)]/50'
                }`}
              >
                {link.label}
              </Link>
            ))}
          </nav>

          {/* Search (desktop) */}
          <div className="hidden lg:block flex-1 max-w-sm ml-6">
            <SearchBar compact />
          </div>

          {/* Theme toggle */}
          <div className="ml-2">
            <ThemeToggle />
          </div>

          {/* Mobile menu button */}
          <button
            className="lg:hidden p-2 rounded-lg text-[var(--text-secondary)] hover:text-[var(--bright-silver)] hover:bg-[var(--dark-steel)]"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="lg:hidden py-3 border-t border-[var(--gunmetal)]">
            <SearchBar className="mb-3" />
            <nav className="flex flex-col gap-1">
              {navLinks.map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isActive(link.href)
                      ? 'bg-[var(--dark-steel)] text-[var(--brrq-gold-light)]'
                      : 'text-[var(--text-secondary)] hover:text-[var(--bright-silver)] hover:bg-[var(--dark-steel)]/50'
                  }`}
                >
                  {link.label}
                </Link>
              ))}
            </nav>
          </div>
        )}
      </div>
    </header>
  );
}
