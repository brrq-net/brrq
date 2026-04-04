'use client';

import Link from 'next/link';
import Image from 'next/image';
import { Zap, Shield, Link2, ArrowRight, Blocks, Activity, Users } from 'lucide-react';
import { useStats } from '@/hooks/useStats';
import { formatNumber } from '@/lib/utils';
import { useEffect, useState } from 'react';

export default function LandingPage() {
  const { data: stats } = useStats();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-[var(--void-black)] relative overflow-hidden font-sans text-[var(--bright-silver)] selection:bg-[var(--brrq-gold)]/30">
      
      {/* Ambient Background Glows */}
      <div className="absolute inset-x-0 top-0 -z-10 transform-gpu overflow-hidden blur-3xl" aria-hidden="true">
        <div className="relative left-[calc(50%-11rem)] aspect-[1155/678] w-[36.125rem] -translate-x-1/2 rotate-[30deg] bg-gradient-to-tr from-[var(--brrq-gold-dark)] to-[#000000] opacity-20 sm:left-[calc(50%-30rem)] sm:w-[72.1875rem]" />
      </div>
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCI+PGRlZnM+PHBhdHRlcm4gaWQ9ImciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTTAgMGg0MHY0MEgweiIgZmlsbD0ibm9uZSIvPjxwYXRoIGQ9Ik0wIDAuNWg0ME0wLjUgMHY0MCIgc3Ryb2tlPSJyZ2JhKDI1NSwyNTUsMjU1LDAuMDMpIi8+PC9wYXR0ZXJuPjwvZGVmcz48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSJ1cmwoI2cpIi8+PC9zdmc+')] opacity-20 pointer-events-none -z-10" />

      {/* Modern Glassy Nav */}
      <header className="fixed top-0 inset-x-0 z-50 border-b border-[var(--border-faint)] bg-[var(--void-black)]/60 backdrop-blur-xl transition-all duration-300">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 sm:h-20 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative flex items-center justify-center p-1.5 rounded-xl bg-gradient-to-br from-[var(--border-subtle)] to-transparent border border-[var(--border-subtle)] group-hover:border-[var(--brrq-gold)]/50 transition-colors shadow-lg">
              <Image src="/logo.png" alt="Brrq" width={28} height={28} className="rounded-md" />
            </div>
            <span className="text-xl sm:text-2xl font-black text-[var(--bright-silver)] tracking-tight group-hover:text-[var(--brrq-gold-light)] transition-colors">Brrq</span>
          </Link>

          <nav className="hidden md:flex items-center gap-8">
            <Link href="/dashboard" className="text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--bright-silver)] transition-colors">Dashboard</Link>
            <Link href="/docs" className="text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--bright-silver)] transition-colors">Docs</Link>
          </nav>

          <div className="flex items-center gap-4">
            <Link
              href="/dashboard"
              className="relative inline-flex items-center justify-center px-4 sm:px-6 py-2 sm:py-2.5 text-sm font-semibold text-[var(--bright-silver)] transition-all bg-gradient-to-r from-[var(--brrq-gold-dark)] to-[var(--brrq-gold)] hover:to-[var(--brrq-gold-light)] border border-[var(--brrq-gold-light)]/30 rounded-full group overflow-hidden shadow-[0_0_15px_rgba(166,100,17,0.3)] hover:shadow-[0_0_25px_rgba(166,100,17,0.5)]"
            >
              <span className="relative z-10 flex items-center gap-2">
                Explore Network
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </span>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="flex-1 flex flex-col items-center justify-center px-4 pt-32 pb-20 sm:pt-48 sm:pb-32 text-center relative z-10 min-h-[90vh]">
        <div className={`max-w-4xl mx-auto transition-all duration-1000 transform ${mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}`}>
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-[var(--brrq-gold)]/30 bg-[var(--brrq-gold)]/10 mb-8 backdrop-blur-sm">
            <span className="flex h-2 w-2 rounded-full bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]" />
            <span className="text-xs font-semibold tracking-wide text-[var(--brrq-gold-light)] uppercase">Pre-Mainnet</span>
          </div>

          <h1 className="text-6xl font-black text-[var(--text-primary)] mb-6 tracking-tighter leading-[1.1] drop-shadow-2xl">
            Brrq
          </h1>
          
          <p className="text-2xl sm:text-3xl md:text-4xl font-extrabold bg-gradient-to-r from-[var(--bright-silver)] via-[var(--brrq-gold-light)] to-[var(--brrq-gold)] bg-clip-text text-transparent mb-6 tracking-tight">
            Bitcoin&apos;s Hash-First Layer 2
          </p>

          <p className="text-lg sm:text-xl text-[var(--text-secondary)] mb-12 max-w-2xl mx-auto font-medium leading-relaxed">
            Instant payments. Post-quantum security. Zero trust assumptions.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-6">
            <Link
              href="/dashboard"
              className="w-full sm:w-auto px-8 py-4 rounded-2xl bg-gradient-to-b from-[var(--brrq-gold)] to-[var(--brrq-gold-dark)] text-[var(--bright-silver)] font-bold text-lg border border-[var(--brrq-gold-light)]/20 shadow-[0_0_30px_rgba(166,100,17,0.3)] hover:shadow-[0_0_40px_rgba(166,100,17,0.5)] hover:-translate-y-1 transition-all duration-300 flex items-center justify-center gap-2"
            >
              Start Exploring
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              href="/docs"
              className="w-full sm:w-auto px-8 py-4 rounded-2xl bg-[var(--bg-subtle)] text-[var(--bright-silver)] font-bold text-lg border border-[var(--border-subtle)] hover:bg-[var(--bg-subtle)] hover:border-[var(--border-subtle)] hover:-translate-y-1 transition-all duration-300 backdrop-blur-md"
            >
              Read Docs
            </Link>
          </div>
        </div>

        {/* Live Stats Bar - Floating */}
        {stats && (
          <div className={`mt-24 grid grid-cols-1 md:grid-cols-3 gap-px bg-[var(--bg-subtle)] rounded-3xl border border-[var(--border-subtle)] overflow-hidden backdrop-blur-xl transition-all duration-1000 delay-300 w-full max-w-5xl mx-auto shadow-2xl ${mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}`}>
            <div className="bg-[var(--void-black)]/60 hover:bg-[var(--void-black)]/80 p-8 flex flex-col items-center justify-center gap-2 transition-colors group">
              <span className="text-[var(--text-tertiary)] text-xs font-bold uppercase tracking-widest flex items-center gap-2 mb-1">
                <Blocks className="w-4 h-4 text-[var(--brrq-gold)] group-hover:scale-110 transition-transform" /> Block Height
              </span>
              <span className="text-4xl font-black text-[var(--text-primary)] tracking-tight drop-shadow-lg">{formatNumber(stats.block_height)}</span>
            </div>
            <div className="bg-[var(--void-black)]/60 hover:bg-[var(--void-black)]/80 p-8 flex flex-col items-center justify-center gap-2 transition-colors group">
              <span className="text-[var(--text-tertiary)] text-xs font-bold uppercase tracking-widest flex items-center gap-2 mb-1">
                <Activity className="w-4 h-4 text-[var(--brrq-gold)] group-hover:scale-110 transition-transform" /> Transactions
              </span>
              <span className="text-4xl font-black text-[var(--text-primary)] tracking-tight drop-shadow-lg">{formatNumber(stats.tx_count)}</span>
            </div>
            <div className="bg-[var(--void-black)]/60 hover:bg-[var(--void-black)]/80 p-8 flex flex-col items-center justify-center gap-2 transition-colors group cursor-default">
              <span className="text-[var(--text-tertiary)] text-xs font-bold uppercase tracking-widest flex items-center gap-2 mb-1">
                <Users className="w-4 h-4 text-[var(--brrq-gold)] group-hover:scale-110 transition-transform" /> Validators
              </span>
              <span className="text-4xl font-black text-[var(--text-primary)] tracking-tight drop-shadow-lg">{formatNumber(stats.validator_count)}</span>
            </div>
          </div>
        )}
      </section>

      {/* Feature Cards */}
      <section className="py-24 px-4 border-t border-[var(--border-faint)] bg-[var(--obsidian)]/30 relative">
        <div className="max-w-6xl mx-auto w-full">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                icon: Zap,
                title: '0ms Payments',
                desc: 'Portal enables instant off-chain payment verification with on-chain settlement security.',
              },
              {
                icon: Shield,
                title: 'Post-Quantum',
                desc: 'SLH-DSA hash-based signatures and Poseidon2 hashing ensure quantum resistance by design.',
              },
              {
                icon: Link2,
                title: 'Bitcoin Native',
                desc: 'BitVM2 trustless bridge with STARK proofs. No federation, no trusted setup.',
              }
            ].map((feat, i) => (
              <div key={i} className="group relative p-8 sm:p-10 rounded-3xl bg-gradient-to-b from-[var(--void-black)] to-[var(--obsidian)] border border-[var(--border-faint)] hover:border-[var(--brrq-gold)]/30 transition-all duration-500 overflow-hidden shadow-xl hover:shadow-[0_10_40px_rgba(166,100,17,0.1)]">
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[var(--brrq-gold)]/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                <div className="relative z-10 flex flex-col items-center text-center">
                  <div className="w-16 h-16 rounded-2xl bg-[var(--graphite)] border border-[var(--border-subtle)] flex items-center justify-center mb-6 group-hover:scale-110 group-hover:border-[var(--brrq-gold)]/50 transition-all duration-500 shadow-inner group-hover:shadow-[0_0_20px_rgba(166,100,17,0.2)]">
                    <feat.icon className="w-8 h-8 text-[var(--brrq-gold-light)]" />
                  </div>
                  <h3 className="text-xl font-bold text-[var(--text-primary)] mb-3 tracking-tight">{feat.title}</h3>
                  <p className="text-[var(--text-secondary)] leading-relaxed">
                    {feat.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[var(--border-faint)] relative z-10 bg-[var(--void-black)]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Image src="/logo.png" alt="Brrq" width={24} height={24} className="rounded" />
              <p className="text-sm text-[var(--text-secondary)]">
                <span className="text-[var(--brrq-gold-light)] font-semibold">Brrq</span> &mdash; Bitcoin L2 with Hash-First Architecture
              </p>
            </div>
            <div className="flex items-center gap-4 text-sm text-[var(--muted-silver)]">
              <a href="https://github.com/brrq-net/brrq" target="_blank" rel="noopener noreferrer" className="hover:text-[var(--brrq-gold-light)] transition-colors">GitHub</a>
              <Link href="/docs" className="hover:text-[var(--brrq-gold-light)] transition-colors">Docs</Link>
              <a href="https://x.com/BrrqNetwork" target="_blank" rel="noopener noreferrer" className="hover:text-[var(--brrq-gold-light)] transition-colors">X</a>
            </div>
          </div>
          <div className="flex items-center justify-center gap-4 text-xs text-[var(--text-tertiary)]">
            <span>SLH-DSA</span>
            <span className="text-[var(--gunmetal)]">·</span>
            <span>ZK-STARK</span>
            <span className="text-[var(--gunmetal)]">·</span>
            <span>BitVM2</span>
            <span className="text-[var(--gunmetal)]">·</span>
            <span>&copy; 2025-2026 Brrq Protocol</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
