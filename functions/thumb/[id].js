import { isAllowedExt, notFoundResponse, parseFileKey } from '../utils/security.js';
import { buildImageHeaders, getFilePath, timeoutSignal } from '../utils/telegram.js';

/**
 * 缩略图通道：后台列表用它，避免每张卡片都去下几 MB 的原图。
 *
 * 缩略图 file_id 在上传时从 Telegram 的 photo 尺寸数组里取最小那张写入 metadata，
 * 所以老记录没有这个字段 —— 直接 302 回落到 /file/ 原图，不会出现裂图。
 */

const THUMB_CACHE_SECONDS = 604800; // 7 天

export async function onRequest(context) {
  const { request, env, params } = context;

  const parsed = parseFileKey(typeof params?.id === 'string' ? params.id : '');
  if (!parsed) return notFoundResponse();

  const { key, ext } = parsed;
  if (ext && !isAllowedExt(ext)) return notFoundResponse();

  const fallbackToOriginal = () =>
    Response.redirect(new URL(`/file/${key}`, request.url).toString(), 302);

  if (!env?.img_url || !env?.TG_Bot_Token) return fallbackToOriginal();

  let metadata = null;
  try {
    metadata = (await env.img_url.getWithMetadata(key))?.metadata || null;
  } catch (error) {
    console.error('thumb: kv read failed', error?.message || error);
  }

  // 黑名单/违规内容连缩略图也不给
  if (metadata?.ListType === 'Block' || metadata?.Label === 'adult') {
    return notFoundResponse();
  }

  if (!metadata?.thumbFileId) return fallbackToOriginal();

  const filePath = await getFilePath(env, metadata.thumbFileId);
  if (!filePath) return fallbackToOriginal();

  let upstream;
  try {
    upstream = await fetch(
      `https://api.telegram.org/file/bot${env.TG_Bot_Token}/${filePath}`,
      {
        headers: { accept: 'image/*' },
        signal: timeoutSignal(),
        cf: { cacheEverything: true, cacheTtl: THUMB_CACHE_SECONDS },
      }
    );
  } catch (error) {
    console.error('thumb: upstream fetch failed', error?.message || error);
    return fallbackToOriginal();
  }

  if (!upstream.ok) return fallbackToOriginal();

  const headers = buildImageHeaders({
    ext,
    key,
    upstream,
    displayName: `thumb-${metadata.fileName || key}`,
    cacheSeconds: THUMB_CACHE_SECONDS,
  });

  return new Response(upstream.body, { status: 200, headers });
}
