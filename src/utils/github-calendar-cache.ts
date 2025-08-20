// GitHub Calendar Cache Utilities
import type { GitHubActivityApiResponse } from '~/types'

const CACHE_PREFIX = 'gh-contrib-'
const CACHE_TTL = 3600000 // 1 hour

export interface CachedData {
  data: GitHubActivityApiResponse
  timestamp: number
}

export function getCacheKey(username: string, year: number | 'last'): string {
  return `${CACHE_PREFIX}${username}-${year}`
}

export function isValidCache(cached: CachedData): boolean {
  return Date.now() - cached.timestamp < CACHE_TTL
}

export async function fetchWithCache(
  username: string,
  year: number | 'last'
): Promise<GitHubActivityApiResponse> {
  const cacheKey = getCacheKey(username, year)
  
  // Try memory cache first (for SSG)
  if (globalThis.__githubContribCache) {
    const cached = globalThis.__githubContribCache.get(cacheKey)
    if (cached && isValidCache(cached)) {
      return cached.data
    }
  }
  
  // Fetch fresh data
  const apiUrl = 'https://github-contributions-api.jogruber.de/v4/'
  const response = await fetch(`${apiUrl}${username}?y=${String(year)}`)
  
  if (!response.ok) {
    throw new Error(`Failed to fetch GitHub contributions for ${username}`)
  }
  
  const data = await response.json() as GitHubActivityApiResponse
  
  // Store in memory cache
  if (!globalThis.__githubContribCache) {
    globalThis.__githubContribCache = new Map()
  }
  
  globalThis.__githubContribCache.set(cacheKey, {
    data,
    timestamp: Date.now()
  })
  
  return data
}

// Declare global cache
declare global {
  var __githubContribCache: Map<string, CachedData> | undefined
}
