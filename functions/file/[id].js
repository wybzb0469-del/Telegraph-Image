import { isAllowedExt, notFoundResponse, parseFileKey } from '../utils/security.js';
import { enforceRateLimit, fileRateRules } from '../utils/rate-limit.js';
import { writeLogThrottled } from '../utils/audit-log.js';
import {
  TELEGRAM_FILE_ID_MIN_LENGTH,
  buildImageHeaders,
  getFilePath,
  timeoutSignal,
} from '../utils/telegram.js';

/**
 * 文件读取/代理。
 *
 * 安全约束：
 *  1. key 必须匹配 <fileId>[.<ext>] 形状，拒绝路径穿越与奇怪字符；
 *  2. 扩展名不在图片白名单 → 直接 404（历史遗留的 .php/.html/.svg 马全部失效）；
 *  3. 不转发用户的 Cookie / Authorization 到 Telegram（旧版会把后台 Basic 凭据泄露给上游）；
 *  4. 强制 Content-Type = 白名单推导值 + nosniff + CSP sandbox，
 *     即使 Telegram 把文件当 text/html 返回，浏览器也不会执行。
 */

export async function onRequest(context) {
  const { request, env, params } = context;

  const rawId = typeof params?.id === 'string' ? params.id : '';
  const parsed = parseFileKey(rawId);
  if (!parsed) return notFoundResponse();

  const { id, key, ext } = parsed;

  // 关键拦截：非图片扩展名一律不服务
  if (ext && !isAllowedExt(ext)) {
    console.warn('file: blocked non-image request', key);
    // 记一条日志便于事后取证；节流到 20 条/分钟，防止被刷爆 KV 写额度
    void writeLogThrottled(
      context,
      {
        action: 'file_blocked',
        ok: false,
        code: 'NON_IMAGE_PATH',
        reason: '非图片扩展名',
        status: 404,
        fileKey: key,
      },
      { bucket: 'file_blocked', maxPerMinute: 20 }
    );
    return notFoundResponse();
  }

  const limited = await enforceRateLimit(context, {
    scope: 'file',
    rules: fileRateRules(env),
    kv: env?.RATE_LIMIT_KV || null,
  });
  if (limited) return limited;

  const url = new URL(request.url);

  // 元数据：先判断黑白名单，命中黑名单就不必回源，省带宽也省 KV 读
  let metadata = null;
  let metadataChanged = false;
  const kv = env?.img_url || null;

  if (kv) {
    try {
      const record = await kv.getWithMetadata(key);
      if (record?.metadata) {
        metadata = record.metadata;
      } else {
        metadata = {
          ListType: 'None',
          Label: 'None',
          TimeStamp: Date.now(),
          liked: false,
          fileName: key,
          fileSize: 0,
        };
        metadataChanged = true;
      }
    } catch (error) {
      console.error('file: kv read failed', error?.message || error);
    }
  }

  if (metadata) {
    if (metadata.ListType === 'Block' || metadata.Label === 'adult') {
      const referer = request.headers.get('Referer');
      const redirectUrl = referer
        ? 'https://static-res.pages.dev/teleimage/img-block-compressed.png'
        : `${url.origin}/block-img.html`;
      return Response.redirect(redirectUrl, 302);
    }

    if (metadata.ListType !== 'White' && env?.WhiteList_Mode === 'true') {
      return Response.redirect(`${url.origin}/whitelist-on.html`, 302);
    }
  }

  const isTelegramHosted = id.length > TELEGRAM_FILE_ID_MIN_LENGTH;
  let fileUrl;
  if (isTelegramHosted) {
    if (!env?.TG_Bot_Token) return notFoundResponse();
    const filePath = await getFilePath(env, id);
    if (!filePath) return notFoundResponse();
    fileUrl = `https://api.telegram.org/file/bot${env.TG_Bot_Token}/${filePath}`;
  } else {
    fileUrl = `https://telegra.ph/${url.pathname}${url.search}`;
  }

  // 只转发安全的请求头，绝不把 Cookie / Authorization 带给上游
  const upstreamHeaders = new Headers();
  for (const name of ['accept', 'range', 'if-none-match', 'if-modified-since']) {
    const value = request.headers.get(name);
    if (value) upstreamHeaders.set(name, value);
  }

  let upstream;
  try {
    upstream = await fetch(fileUrl, {
      method: request.method === 'HEAD' ? 'HEAD' : 'GET',
      headers: upstreamHeaders,
      redirect: 'follow',
      signal: timeoutSignal(),
      // 图片内容不可变：走边缘缓存，重复访问不再回源 Telegram。
      // 带 Range 的请求（视频拖动/断点续传）跳过，避免缓存碎片。
      ...(request.headers.get('range')
        ? {}
        : { cf: { cacheEverything: true, cacheTtl: 86400 } }),
    });
  } catch (error) {
    console.error('file: upstream fetch failed', error?.message || error);
    return notFoundResponse();
  }

  if (!upstream.ok && upstream.status !== 304) {
    return notFoundResponse();
  }

  const headers = buildImageHeaders({
    ext,
    key,
    upstream,
    displayName: metadata?.fileName || key,
  });

  // 内容审查（仅 Telegraph 源可用，需要公网可访问 URL）
  if (metadata && metadata.ListType !== 'White' && !isTelegramHosted && env?.ModerateContentApiKey) {
    try {
      const moderateUrl = `https://api.moderatecontent.com/moderate/?key=${env.ModerateContentApiKey}&url=https://telegra.ph${url.pathname}${url.search}`;
      const moderateResponse = await fetch(moderateUrl, { signal: timeoutSignal(8000) });
      if (moderateResponse.ok) {
        const moderateData = await moderateResponse.json();
        if (moderateData?.rating_label) {
          metadata.Label = moderateData.rating_label;
          metadataChanged = true;
          if (moderateData.rating_label === 'adult') {
            await safePut(kv, key, metadata);
            return Response.redirect(`${url.origin}/block-img.html`, 302);
          }
        }
      } else {
        console.error('file: moderation request failed', moderateResponse.status);
      }
    } catch (error) {
      // 审查失败不影响正常出图
      console.error('file: moderation error', error?.message || error);
    }
  }

  // 只有元数据真的变化时才写 KV —— 旧版每次请求都 put，
  // 一天 1000 次的免费写入额度很容易被打满，等于自伤。
  if (metadata && metadataChanged) {
    await safePut(kv, key, metadata);
  }

  if (upstream.status === 304) {
    return new Response(null, { status: 304, headers });
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers,
  });
}

async function safePut(kv, key, metadata) {
  if (!kv) return;
  try {
    await kv.put(key, '', { metadata });
  } catch (error) {
    console.error('file: kv put failed', error?.message || error);
  }
}
