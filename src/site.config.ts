import type { SiteConfig } from '~/types'

const config: SiteConfig = {
  // Absolute URL to the root of your published site, used for generating links and sitemaps.
  site: 'https://www.rahalkar.dev',
  // The name of your site, used in the title and for SEO.
  title: 'Chaitanya Rahalkar',
  // The description of your site, used for SEO and RSS feed.
  description:
    'Software Security Engineer at Block Inc., specializing in cloud-native security and application security',
  // The author of the site, used in the footer, SEO, and RSS feed.
  author: 'Chaitanya Rahalkar',
  // Keywords for SEO, used in the meta tags.
  tags: [
    'Security',
    'Cloud',
    'Software Engineering',
    'Cybersecurity',
    'Application Security',
    'Cloud-Native',
  ],
  // Path to the image used for generating social media previews.
  // Needs to be a square JPEG file due to limitations of the social card generator.
  // Try https://squoosh.app/ to easily convert images to JPEG.
  socialCardAvatarImage: './src/content/avatar.jpg',
  // Font imported from @fontsource or elsewhere, used for the entire site.
  // To change this see src/styles/global.css and import a different font.
  font: 'JetBrains Mono Variable',
  // For pagination, the number of posts to display per page.
  // The homepage will display half this number in the "Latest Posts" section.
  pageSize: 6,
  // Whether Astro should resolve trailing slashes in URLs or not.
  // This value is used in the astro.config.mjs file and in the "Search" component to make sure pagefind links match this setting.
  // It is not recommended to change this, since most links existing in the site currently do not have trailing slashes.
  trailingSlashes: false,
  // The navigation links to display in the header.
  navLinks: [
    {
      name: 'Home',
      url: '/',
    },
    {
      name: 'About',
      url: '/about',
    },
    {
      name: 'Blog',
      url: '/posts',
    },
    {
      name: 'Publications',
      url: '/publications',
    },
    {
      name: 'Talks',
      url: '/talks',
    },
    {
      name: 'Resume',
      url: 'https://rahalkar.dev/files/cv.pdf',
      external: true,
    },
  ],
  // The theming configuration for the site.
  themes: {
    // The theming mode. One of "single" | "select" | "light-dark-auto".
    mode: 'select',
    // The default theme identifier, used when themeMode is "select" or "light-dark-auto".
    // Make sure this is one of the themes listed in `themes` or "auto" for "light-dark-auto" mode.
    // "vitesse-black" is repainted into the Block palette below (see `overrides`).
    default: 'vitesse-black',
    // Shiki themes to bundle with the site.
    // https://expressive-code.com/guides/themes/#using-bundled-themes
    // These will be used to theme the entire site along with syntax highlighting.
    // To use light-dark-auto mode, only include a light and a dark theme in that order.
    // include: [
    //   'github-light',
    //   'github-dark',
    // ]
    include: [
      'andromeeda',
      'aurora-x',
      'ayu-dark',
      'catppuccin-frappe',
      'catppuccin-latte',
      'catppuccin-macchiato',
      'catppuccin-mocha',
      'dark-plus',
      'dracula',
      'dracula-soft',
      'everforest-dark',
      'everforest-light',
      'github-dark',
      'github-dark-default',
      'github-dark-dimmed',
      'github-dark-high-contrast',
      'github-light',
      'github-light-default',
      'github-light-high-contrast',
      'gruvbox-dark-hard',
      'gruvbox-dark-medium',
      'gruvbox-dark-soft',
      'gruvbox-light-hard',
      'gruvbox-light-medium',
      'gruvbox-light-soft',
      'houston',
      'kanagawa-dragon',
      'kanagawa-lotus',
      'kanagawa-wave',
      'laserwave',
      'light-plus',
      'material-theme',
      'material-theme-darker',
      'material-theme-lighter',
      'material-theme-ocean',
      'material-theme-palenight',
      'min-dark',
      'min-light',
      'monokai',
      'night-owl',
      'nord',
      'one-dark-pro',
      'one-light',
      'plastic',
      'poimandres',
      'red',
      'rose-pine',
      'rose-pine-dawn',
      'rose-pine-moon',
      'slack-dark',
      'slack-ochin',
      'snazzy-light',
      'solarized-dark',
      'solarized-light',
      'synthwave-84',
      'tokyo-night',
      'vesper',
      'vitesse-black',
      'vitesse-dark',
      'vitesse-light',
    ],
    // Optional overrides for specific themes to customize colors.
    // Their values can be either a literal color (hex, rgb, hsl) or another theme key.
    // See themeKeys list in src/types.ts for available keys to override and reference.
    overrides: {
      // "Block Terminal" — the palette from Block's engineering blog
      // (engineering.block.xyz/blog), painted over the vitesse-black base so
      // code blocks keep a pure-black background. Pure black page, #1a1a1a
      // surfaces, #333 hairlines, dim #888 metadata, and the Block brand
      // accents: green prompt, blue links, purple list markers.
      'vitesse-black': {
        background: '#000000', // --block-black
        foreground: '#e0e0e0', // --term-text
        accent: '#00c244', // --block-green, the terminal prompt colour
        link: '#0284c7', // --block-blue
        heading1: '#ffffff', // --block-white
        heading2: '#ffffff',
        heading3: '#ffffff',
        heading4: '#e0e0e0',
        heading5: '#999999', // --block-gray-light
        heading6: '#999999',
        list: '#8b46ff', // --block-purple
        separator: '#333333', // --term-border
        italic: '#999999',
        note: '#0284c7',
        tip: '#00c244',
        important: '#8b46ff',
        caution: '#ff3b30', // --block-red
        warning: '#ffbb00', // --block-yellow
        blue: '#0284c7',
        green: '#00c244',
        red: '#ff3b30',
        yellow: '#ffbb00',
        magenta: '#ff4e98', // --block-pink
        cyan: '#22d3ee',
      },
      // Improve readability for aurora-x theme
      // 'aurora-x': {
      //   background: '#292929FF',
      //   foreground: '#DDDDDDFF',
      //   warning: '#FF7876FF',
      //   important: '#FF98FFFF',
      //   note: '#83AEFFFF',
      // },
      // Make the GitHub dark theme a little cuter
      // 'github-light': {
      //   accent: 'magenta',
      //   heading1: 'magenta',
      //   heading2: 'magenta',
      //   heading3: 'magenta',
      //   heading4: 'magenta',
      //   heading5: 'magenta',
      //   heading6: 'magenta',
      //   separator: 'magenta',
      //   link: 'list',
      // },
    },
    // Optional display names for the theme picker. Themes without an entry
    // fall back to a title-cased version of their identifier.
    labels: {
      'vitesse-black': 'Block Terminal',
    },
  },
  // Social links to display in the footer.
  socialLinks: {
    github: 'https://github.com/chaitanyarahalkar',
    mastodon: undefined,
    email: 'mailto:c@rahalkar.dev',
    linkedin: undefined,
    bluesky: undefined,
    twitter: 'https://x.com/chairahalkar',
    rss: true, // Set to true to include an RSS feed link in the footer
  },
  // Configuration for Giscus comments.
  // To set up Giscus, follow the instructions at https://giscus.app/
  // You'll need a GitHub repository with discussions enabled and the Giscus app installed.
  // Take the values from the generated script tag at https://giscus.app and fill them in here.
  // If you don't want to use Giscus, set this to undefined.
  giscus: undefined,
}

export default config
