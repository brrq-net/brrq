import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { QueryProvider } from '@/components/providers/QueryProvider';

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'Brrq — Bitcoin\'s Hash-First Layer 2',
  description: 'Block explorer and dashboard for the Brrq Bitcoin L2 network',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.className} suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('brrq-theme');if(t==='light'){document.documentElement.setAttribute('data-theme','light')}}catch(e){}})();`,
          }}
        />
      </head>
      <body className="min-h-screen bg-[var(--void-black)] text-[var(--bright-silver)] flex flex-col">
        <QueryProvider>
          {children}
        </QueryProvider>
      </body>
    </html>
  );
}
