import { jsonResponse } from '../utils/security.js';
import { enforceRateLimit } from '../utils/rate-limit.js';

/**
 * 自检接口：GET /api/health
 *
 * 只返回布尔值和状态码，不泄露任何密钥内容。
 * 上传报错时先看这里：
 *  - bindings.TG_Bot_Token/Chat_ID 是否 true
 *  - telegram.ok 是否 true（false 说明 Bot Token 失效或被网络阻断）
 *  - kv 是否可读写（false 说明 KV 绑定/配额有问题）
 */
export async function onRequest(context) {
  const { env } = context;

  const limited = await enforceRateLimit(context, {
    scope: 'health',
    rules: [{ name: 'min', limit: 30, windowSec: 60 }],
    kv: env?.RATE_LIMIT_KV || null,
  });
  if (limited) return limited;

  const bindings = {
    TG_Bot_Token: Boolean(env?.TG_Bot_Token),
    TG_Chat_ID: Boolean(env?.TG_Chat_ID),
    img_url: Boolean(env?.img_url),
    BASIC_USER: Boolean(env?.BASIC_USER),
    RATE_LIMIT_KV: Boolean(env?.RATE_LIMIT_KV),
  };

  let telegram = { reachable: false, ok: false, status: 0, error: null };
  if (env?.TG_Bot_Token) {
    const startedAt = Date.now();
    try {
      const res = await fetch(`https://api.telegram.org/bot${env.TG_Bot_Token}/getMe`, {
        signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout
          ? AbortSignal.timeout(8000)
          : undefined,
      });
      let data = null;
      try {
        data = await res.json();
      } catch (error) {
        data = null;
      }
      telegram = {
        reachable: true,
        ok: Boolean(data?.ok),
        status: res.status,
        error: data?.ok ? null : data?.description || `HTTP ${res.status}`,
      };
    } catch (error) {
      telegram.error = error?.name === 'TimeoutError' ? 'timeout (8s)' : error?.message || 'network error';
    }
    telegram.latencyMs = Date.now() - startedAt;
  }

  let kv = { bound: Boolean(env?.img_url), readable: false, writable: false };
  if (env?.img_url) {
    try {
      await env.img_url.get('__health_probe__');
      kv.readable = true;
    } catch (error) {
      kv.readError = error?.message || 'read failed';
    }
  }

  const ok = bindings.TG_Bot_Token && bindings.TG_Chat_ID && telegram.ok;

  return jsonResponse({
    ok,
    bindings,
    telegram,
    kv,
    maxUploadBytes: Number(env?.MAX_UPLOAD_SIZE) > 0 ? Number(env.MAX_UPLOAD_SIZE) : 10 * 1024 * 1024,
    time: new Date().toISOString(),
  });
}
