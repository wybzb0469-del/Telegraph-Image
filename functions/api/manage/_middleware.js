import { constantTimeEquals, crossSiteReason, jsonResponse } from '../../utils/security.js';
import { enforceRateLimit, loginRateRules } from '../../utils/rate-limit.js';

/**
 * 后台 API 统一鉴权中间件。
 *
 * 相比旧版的改动：
 *  1. 增加跨站来源校验（CSRF）—— Basic 凭据会被浏览器自动附带，
 *     第三方页面用 <img src=".../api/manage/delete/KEY"> 就能借管理员身份删记录；
 *  2. 凭据比较改为 SHA-256 定长比较，避免计时侧信道；
 *  3. Basic 认证失败按 IP 限流，挡暴力破解；
 *  4. 异常只回通用信息，不再把堆栈吐给客户端；
 *  5. 可选 ADMIN_REQUIRE_AUTH=true 强制执行鉴权（未配置账号时直接拒绝，而不是裸奔）。
 */

async function errorHandling(context) {
  try {
    return await context.next();
  } catch (err) {
    console.error('manage api error:', err?.stack || err?.message || err);
    return new Response('Internal Server Error', {
      status: 500,
      headers: { 'Content-Type': 'text/plain;charset=UTF-8', 'Cache-Control': 'no-store' },
    });
  }
}

function unauthorized(reason) {
  return new Response(reason, {
    status: 401,
    statusText: 'Unauthorized',
    headers: {
      'Content-Type': 'text/plain;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Content-Length': String(new TextEncoder().encode(reason).length),
      'WWW-Authenticate': 'Basic realm="Telegraph-Image Admin", charset="UTF-8"',
    },
  });
}

function badRequest(reason) {
  return new Response(reason, {
    status: 400,
    statusText: 'Bad Request',
    headers: {
      'Content-Type': 'text/plain;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Content-Length': String(new TextEncoder().encode(reason).length),
    },
  });
}

function parseBasicAuth(request) {
  const header = request.headers.get('Authorization');
  if (!header) return null;

  const [scheme, encoded] = header.split(' ');
  if (!encoded || scheme !== 'Basic') throw new Error('malformed');

  let decoded;
  try {
    const buffer = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    decoded = new TextDecoder().decode(buffer).normalize();
  } catch (error) {
    throw new Error('malformed');
  }

  const index = decoded.indexOf(':');
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) throw new Error('malformed');

  return {
    user: decoded.substring(0, index),
    pass: decoded.substring(index + 1),
  };
}

async function authentication(context) {
  const { env, request } = context;

  // 0) 先挡跨站请求，避免 Basic 凭据被第三方页面"借用"
  const url = new URL(request.url);
  const crossSite = crossSiteReason(request, url);
  if (crossSite) {
    console.warn('manage: 已拦截跨站请求', crossSite);
    return jsonResponse({ error: '跨站请求被拒绝' }, 403);
  }

  // 未绑定 KV 时后台功能整体关闭
  if (!env?.img_url) {
    return new Response('Dashboard is disabled. Please bind a KV namespace to use this feature.', {
      status: 200,
    });
  }

  const userConfigured = typeof env.BASIC_USER === 'string' && env.BASIC_USER.length > 0;
  const passConfigured = typeof env.BASIC_PASS === 'string' && env.BASIC_PASS.length > 0;
  const authEnabled = userConfigured && passConfigured;

  // 收紧开关：强制鉴权，避免忘记配置账号导致后台裸奔
  if (!authEnabled) {
    if (env.ADMIN_REQUIRE_AUTH === 'true') {
      return unauthorized('Admin credentials are not configured. Set BASIC_USER / BASIC_PASS.');
    }
    return context.next();
  }

  let credentials;
  try {
    credentials = parseBasicAuth(request);
  } catch (error) {
    return badRequest('Malformed authorization header.');
  }

  if (!credentials) {
    return unauthorized('You need to login.');
  }

  const [userOk, passOk] = await Promise.all([
    constantTimeEquals(credentials.user, env.BASIC_USER),
    constantTimeEquals(credentials.pass, env.BASIC_PASS),
  ]);

  if (!userOk || !passOk) {
    // 认证失败计数，超限直接 429（仅在 KV 或内存计数范围内）
    const limited = await enforceRateLimit(context, {
      scope: 'admin-login',
      rules: loginRateRules(env),
      kv: env?.RATE_LIMIT_KV || null,
    });
    if (limited) return limited;

    console.warn('manage: auth failed from', request.headers.get('cf-connecting-ip') || 'unknown');
    return unauthorized('Invalid credentials.');
  }

  return context.next();
}

export const onRequest = [errorHandling, authentication];
