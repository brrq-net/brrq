'use client';

import { useEffect, useState } from 'react';
import { Sun, Moon } from 'lucide-react';

type Theme = 'dark' | 'light';

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>('dark');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const stored = document.documentElement.getAttribute('data-theme') as Theme | null;
    if (stored === 'light') {
      setTheme('light');
    } else {
      setTheme('dark');
    }
  }, []);

  function toggleTheme() {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    // Enable transition class
    document.documentElement.classList.add('theme-transition');
    if (next === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem('brrq-theme', next);
    setTheme(next);
    // Remove transition class after animation
    setTimeout(() => {
      document.documentElement.classList.remove('theme-transition');
    }, 350);
  }

  // Prevent hydration mismatch — render nothing until mounted
  if (!mounted) {
    return <div className="w-8 h-8" />;
  }

  return (
    <button
      onClick={toggleTheme}
      className="p-1.5 rounded-lg text-[var(--text-secondary)] hover:text-[var(--brrq-gold-light)] hover:bg-[var(--dark-steel)] transition-colors"
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
    >
      {theme === 'dark' ? (
        <Sun className="h-4.5 w-4.5" />
      ) : (
        <Moon className="h-4.5 w-4.5" />
      )}
    </button>
  );
}
