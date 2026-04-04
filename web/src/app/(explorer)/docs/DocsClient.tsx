'use client';

import { useState } from 'react';
import { Book, ChevronRight } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface DocEntry {
  slug: string;
  title: string;
  content: string;
}

interface DocsClientProps {
  docs: DocEntry[];
}

export default function DocsClient({ docs }: DocsClientProps) {
  const [activeSlug, setActiveSlug] = useState(docs[0]?.slug ?? '');

  const activeDoc = docs.find((d) => d.slug === activeSlug);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">Documentation</h1>
        <p className="text-[var(--text-secondary)]">Brrq technical documentation and guides</p>
      </div>

      {/* Mobile selector */}
      <div className="lg:hidden">
        <select
          value={activeSlug}
          onChange={(e) => setActiveSlug(e.target.value)}
          className="w-full bg-[var(--obsidian)] border border-[var(--gunmetal)] rounded-lg px-4 py-2 text-[var(--bright-silver)] focus:outline-none focus:border-[var(--brrq-gold)]"
        >
          {docs.map((doc) => (
            <option key={doc.slug} value={doc.slug}>
              {doc.title}
            </option>
          ))}
        </select>
      </div>

      <div className="flex gap-8">
        {/* Sidebar (desktop) */}
        <aside className="w-56 shrink-0 hidden lg:block">
          <nav className="sticky top-24 space-y-1 bg-[var(--obsidian)] rounded-xl p-3 gold-border">
            <h2 className="text-xs font-semibold text-[var(--muted-silver)] uppercase tracking-wider mb-3 flex items-center gap-2 px-3">
              <Book className="h-3.5 w-3.5" />
              Guides
            </h2>
            {docs.map((doc) => (
              <button
                key={doc.slug}
                onClick={() => setActiveSlug(doc.slug)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 ${
                  activeSlug === doc.slug
                    ? 'bg-[var(--brrq-gold)]/10 text-[var(--brrq-gold-light)] font-medium'
                    : 'text-[var(--text-secondary)] hover:text-[var(--bright-silver)] hover:bg-[var(--dark-steel)]'
                }`}
              >
                <ChevronRight
                  className={`h-3 w-3 shrink-0 transition-transform ${
                    activeSlug === doc.slug ? 'rotate-90' : ''
                  }`}
                />
                {doc.title}
              </button>
            ))}
          </nav>
        </aside>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <article className="prose-brrq">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {activeDoc?.content ?? 'Document not found.'}
            </ReactMarkdown>
          </article>
        </div>
      </div>
    </div>
  );
}
