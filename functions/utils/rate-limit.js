/**
 * 轻量限流器。
 *
 * 分两层：
 *  1) 内存滑动窗口（每个 Worker isolate 独立）—— 零成本、挡得住单点突发；
 *  2) 可选 KV 计数（绑定 RATE_LIMIT_KV 时启用）—— 跨 isolate 生效。
 *
 * 注意：Cloudflare Pages Functions 免费版没有 Durable Objects，内存层只在单个
 * isolate 内有效，因此**真正的兜底一定是 Cloudflare WAF 速率限制规则**，
 * 代码这层是纵深防御。详见 SECURITY.md。
 */

import { clientIp, intEnv, jsonResponse } from './security.js';

const buckets = new Map();
const MAX_BUCKETS = 20000;

function prune(now) {
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
  }
}

function hitMemory(key, windowMs, now) {
  let bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    if (buckets.size >= MAX_BUCKETS) prune(now);
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }
  bucket.count += 1;
  return bucket;
}

async function hitKv(kv, key, windowSec) {
  // KV 的 expirationTtl 最小 60 秒
  const ttl = Math.max(60, Math.ceil(windowSec));
  const current = Number(await kv.get(key)) || 0;
  const next = current + 1;
  await kv.put(key, String(next), { expirationTtl: ttl });
  return next;
}

function tooManyRequests(retryAfter) {
  return jsonResponse(
    {
      error: `请求过于频繁，请 ${retryAfter} 秒后再试`,
      code: 'RATE_LIMITED',
    },
    429,
    { 'Retry-After': String(retryAfter) }
  );
}

/**
 * @param {object} context Pages Functions context
 * @param {object} options
 * @param {string} options.scope 限流作用域名，如 'upload'
 * @param {Array<{name:string, limit:number, windowSec:number, global?:boolean}>} options.rules
 * @param {KVNamespace|null} options.kv 可选的跨 isolate 计数器
 * @returns {Promise<Response|null>} 超限返回 429 响应，否则 null
 */
export async function enforceRateLimit(context, { scope = 'default', rules = [], kv = null } = {}) {
  const { request, env } = context;
  if (String(env?.RATE_LIMIT_ENABLED || '').toLowerCase() === 'false') return null;
  if (!rules.length) return null;

  const ip = clientIp(request);
  const now = Date.now();

  for (const rule of rules) {
    const limit = Number(rule.limit);
    if (!Number.isFinite(limit) || limit <= 0) continue;

    const windowSec = Math.max(1, Number(rule.windowSec) || 60);
    const windowMs = windowSec * 1000;
    const slot = Math.floor(now / windowMs);
    const subject = rule.global ? 'global' : ip;
    const key = `rl:${scope}:${rule.name}:${subject}:${slot}`;

    let count = hitMemory(key, windowMs, now).count;

    if (kv && typeof kv.get === 'function') {
      try {
        // KV 内部 key 保持短且无特殊字符，避免超长 key
        const kvKey = key.replace(/[^A-Za-z0-9:_.-]/g, '_').slice(0, 400);
        count = Math.max(count, await hitKv(kv, kvKey, windowSec));
      } catch (error) {
        // 计数器故障不能阻断正常业务
        console.error('rate limit kv error:', error?.message || error);
      }
    }

    if (count > limit) {
      const retryAfter = Math.max(1, Math.ceil(((slot + 1) * windowMs - now) / 1000));
      return tooManyRequests(retryAfter);
    }
  }

  return null;
}

/** 上传接口限流规则：分钟级 + 日级 + 全站级 */
export function uploadRateRules(env = {}) {
  return [
    {
      name: 'min',
      limit: intEnv(env.UPLOAD_RATE_LIMIT, 10, { min: 1, max: 600 }),
      windowSec: intEnv(env.UPLOAD_RATE_WINDOW, 60, { min: 10, max: 3600 }),
    },
    {
      name: 'day',
      limit: intEnv(env.UPLOAD_DAILY_LIMIT, 300, { min: 1, max: 100000 }),
      windowSec: 86400,
    },
    {
      name: 'all',
      global: true,
      limit: intEnv(env.UPLOAD_GLOBAL_RATE_LIMIT, 300, { min: 1, max: 100000 }),
      windowSec: 60,
    },
  ];
}

/** 后台登录（Basic 认证失败）限流规则 */
export function loginRateRules(env = {}) {
  return [
    {
      name: 'fail',
      limit: intEnv(env.LOGIN_RATE_LIMIT, 10, { min: 1, max: 100 }),
      windowSec: intEnv(env.LOGIN_RATE_WINDOW, 300, { min: 30, max: 86400 }),
    },
  ];
}

/**
 * 图片读取限流：默认关闭（图床本来就要被大量读取）。
 * 只有显式设置 FILE_RATE_LIMIT 大于 0 才生效，防止被当成免费 CDN 刷流量。
 */
export function fileRateRules(env = {}) {
  const limit = Number(env.FILE_RATE_LIMIT) || 0;
  if (limit <= 0) return [];
  return [
    {
      name: 'read',
      limit: Math.min(Math.max(Math.floor(limit), 10), 100000),
      windowSec: intEnv(env.FILE_RATE_WINDOW, 60, { min: 10, max: 3600 }),
    },
  ];
}

/** 仅供单元测试重置内存计数 */
export function __resetRateLimitStore() {
  buckets.clear();
}
