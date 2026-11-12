/**
 * 上传/拦截审计日志。
 *
 * 存储：KV 里每条日志一个 key，key 用「时间取反」保证 list 出来的顺序就是
 * 从新到旧（KV list 按字典序升序返回），日志内容放在 metadata 里，
 * 这样列表页一次 list 就能拿到全部字段，不需要逐条 get。
 *
 * 成本：每条日志 1 次 KV 写；列表页 1 次 KV list。
 * KV metadata 上限 1KB，所以所有字符串字段都做了截断。
 */

import { clientIp } from './security.js';

const TS_MAX = 9999999999999;
const PREFIX = 'log:';

function kvOf(env) {
  return env?.LOG_KV || env?.img_url || null;
}

export function logEnabled(env) {
  if (String(env?.LOG_ENABLED || '').toLowerCase() === 'false') return false;
  return Boolean(kvOf(env));
}

function clip(value, max) {
  if (value === undefined || value === null) return null;
  const s = String(value).replace(/[\u0000-\u001F\u007F]/g, ' ');
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

async function maybeHashIp(env, ip) {
  if (String(env?.LOG_HASH_IP || '').toLowerCase() !== 'true') return ip;
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip));
    return [...new Uint8Array(buf)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch (error) {
    return ip;
  }
}

/**
 * @param {object} context Pages Functions context
 * @param {object} event { action, ok, code, reason, fileKey, fileName, fileSize, mime, status, durationMs }
 */
export async function writeLog(context, event = {}) {
  const { env, request } = context;
  if (!logEnabled(env)) return;

  const kv = kvOf(env);
  const cf = request.cf || {};
  const url = new URL(request.url);
  const now = Date.now();

  const entry = {
    ts: now,
    action: clip(event.action || 'unknown', 24),
    ok: event.ok !== false,
    code: clip(event.code, 24),
    status: event.status || null,
    ip: clip(await maybeHashIp(env, clientIp(request)), 45),
    country: clip(cf.country, 4),
    city: clip(cf.city, 32),
    colo: clip(cf.colo, 6),
    asn: cf.asn || null,
    ua: clip(request.headers.get('user-agent'), 180),
    referer: clip(request.headers.get('referer'), 120),
    origin: clip(request.headers.get('origin'), 60),
    path: clip(url.pathname, 60),
    method: request.method,
    fileKey: clip(event.fileKey, 70),
    fileName: clip(event.fileName, 60),
    fileSize: Number(event.fileSize) || null,
    mime: clip(event.mime, 24),
    reason: clip(event.reason, 60),
    durationMs: event.durationMs ?? null,
  };

  const key = `${PREFIX}${String(TS_MAX - now).padStart(13, '0')}:${Math.random().toString(36).slice(2, 6)}`;
  const ttlDays = Math.max(1, Math.min(Number(env?.LOG_RETENTION_DAYS) || 30, 365));

  const task = kv
    .put(key, '', { metadata: entry, expirationTtl: ttlDays * 86400 })
    .catch((error) => console.error('log: write failed', error?.message || error));

  // 不阻塞响应；Pages Functions 提供了 waitUntil
  if (typeof context.waitUntil === 'function') context.waitUntil(task);
  else await task;
}

/** 简单节流：同一 bucket 每分钟最多 maxPerMinute 条，避免被刷爆 KV 配额 */
const throttleState = new Map();

export async function writeLogThrottled(context, event, { bucket = 'default', maxPerMinute = 30 } = {}) {
  const minute = Math.floor(Date.now() / 60000);
  const key = `${bucket}:${minute}`;
  const used = throttleState.get(key) || 0;
  if (used >= maxPerMinute) return;
  throttleState.set(key, used + 1);

  if (throttleState.size > 500) {
    for (const k of throttleState.keys()) {
      if (!k.endsWith(`:${minute}`)) throttleState.delete(k);
    }
  }

  await writeLog(context, event);
}

/**
 * 读取日志（从新到旧）。
 * @returns {{enabled:boolean, entries:Array, complete:boolean, cursor?:string}}
 */
export async function readLogs(env, { limit = 100, cursor } = {}) {
  const kv = kvOf(env);
  if (!kv) return { enabled: false, entries: [], complete: true };

  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const res = await kv.list({ prefix: PREFIX, limit: safeLimit, cursor });
  const entries = (res.keys || []).map((k) => ({
    ...(k.metadata || {}),
    expiresAt: k.expiration ? k.expiration * 1000 : null,
  }));

  return {
    enabled: true,
    entries,
    complete: Boolean(res.list_complete),
    cursor: res.cursor,
  };
}

/** 清空日志（KV 免费版每天 1000 次删除，所以分批） */
export async function clearLogs(env, { max = 200 } = {}) {
  const kv = kvOf(env);
  if (!kv) return { deleted: 0, complete: true };

  const res = await kv.list({ prefix: PREFIX, limit: Math.min(Math.max(max, 1), 1000) });
  const keys = (res.keys || []).map((k) => k.name);

  let deleted = 0;
  for (const key of keys) {
    try {
      await kv.delete(key);
      deleted += 1;
    } catch (error) {
      console.error('log: delete failed', key, error?.message || error);
    }
  }

  return { deleted, complete: Boolean(res.list_complete) };
}
