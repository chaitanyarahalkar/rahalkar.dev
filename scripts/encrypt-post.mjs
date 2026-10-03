// Encrypts a Markdown post for password-protected publishing.
//
//   POST_PASSWORD='long passphrase' node scripts/encrypt-post.mjs protected/my-post.md
//
// The Markdown is rendered to HTML here, then encrypted with AES-256-GCM using a
// key derived from the password via PBKDF2-SHA256. Only the resulting JSON
// (src/content/protected/<slug>.json) is committed; the plaintext source stays in
// the gitignored protected/ folder. The browser decrypts it on /protected/<slug>.
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { webcrypto as crypto } from 'node:crypto'
import {
  createMarkdownProcessor,
  parseFrontmatter,
  rehypeHeadingIds,
} from '@astrojs/markdown-remark'
import rehypeExternalLinks from 'rehype-external-links'

const ITERATIONS = 600_000
const outDir = path.join(process.cwd(), 'src/content/protected')

const source = process.argv[2]
const password = process.env.POST_PASSWORD
if (!source || !password) {
  console.error("Usage: POST_PASSWORD='...' node scripts/encrypt-post.mjs <post.md>")
  process.exit(1)
}

const { frontmatter, content } = parseFrontmatter(fs.readFileSync(source, 'utf8'))
const processor = await createMarkdownProcessor({
  syntaxHighlight: 'shiki',
  shikiConfig: { theme: 'vitesse-black' },
  rehypePlugins: [
    rehypeHeadingIds,
    [rehypeExternalLinks, { rel: ['noreferrer', 'noopener'], target: '_blank' }],
  ],
})
const { code: html } = await processor.render(content)
const { title, published, hint } = frontmatter
if (!title || !published) {
  console.error('Frontmatter must include `title` and `published`.')
  process.exit(1)
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64')
const salt = crypto.getRandomValues(new Uint8Array(16))
const iv = crypto.getRandomValues(new Uint8Array(12))
const baseKey = await crypto.subtle.importKey(
  'raw',
  new TextEncoder().encode(password),
  'PBKDF2',
  false,
  ['deriveKey'],
)
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
  baseKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt'],
)
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv },
  key,
  new TextEncoder().encode(html),
)

const slug = path.basename(source).replace(/\.mdx?$/, '')
const out = {
  title,
  published: new Date(published).toISOString().slice(0, 10),
  ...(hint ? { hint } : {}),
  kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt: b64(salt) },
  iv: b64(iv),
  ciphertext: b64(new Uint8Array(ciphertext)),
}
fs.mkdirSync(outDir, { recursive: true })
const outPath = path.join(outDir, `${slug}.json`)
fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n')
console.log(
  `Encrypted ${source} -> ${path.relative(process.cwd(), outPath)} (/protected/${slug})`,
)
