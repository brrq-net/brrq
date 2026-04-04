import fs from 'fs';
import path from 'path';
import DocsClient from './DocsClient';

const DOCS = [
  { slug: 'whitepaper', title: 'Whitepaper', file: 'whitepaper.md' },
  { slug: 'litepaper', title: 'Litepaper', file: 'litepaper.md' },
  { slug: 'portal-whitepaper', title: 'Portal Whitepaper', file: 'portal-whitepaper.md' },
  { slug: 'yellow-paper', title: 'Yellow Paper', file: 'yellow-paper.md' },
  { slug: 'economic-specification', title: 'Economic Specification', file: 'BRRQ_ECONOMIC_SPECIFICATION.md' },
  { slug: 'quickstart', title: 'Quickstart', file: 'QUICKSTART.md' },
  { slug: 'developer-guide', title: 'Developer Guide', file: 'developer-guide.md' },
  { slug: 'api-reference', title: 'API Reference', file: 'API-REFERENCE.md' },
  { slug: 'portal-guide', title: 'Portal Guide', file: 'PORTAL-GUIDE.md' },
  { slug: 'testnet-guide', title: 'Testnet Guide', file: 'testnet-guide.md' },
];

export default function DocsPage() {
  const docsDir = path.join(process.cwd(), '..', 'docs');

  const docs = DOCS.map((doc) => {
    let content = 'Document not available.';
    try {
      const filePath = path.join(docsDir, doc.file);
      content = fs.readFileSync(filePath, 'utf-8');
    } catch { /* file missing */ }
    return { slug: doc.slug, title: doc.title, content };
  });

  return <DocsClient docs={docs} />;
}
