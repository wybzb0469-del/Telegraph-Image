import { jsonResponse } from '../../../utils/security.js';
import { enforceRateLimit } from '../../../utils/rate-limit.js';

/**
 * Bing 每日壁纸代理。
 *
 * 旧版的问题：每个访客都回源一次 Bing、没有超时、没有限流，
 * 既能被当成免费代理刷别人的接口，也会把函数时长耗在等第三方上。
 * 现在：边缘缓存 1 小时 + 8s 超时 + 按 IP 限流 + 失败降级为空数组。
 */

const BING_URL = 'https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5';

export async function onRequest(context) {
  const { env } = context;

  const limited = await enforceRateLimit(context, {
    scope: 'wallpaper',
    rules: [
      {
        name: 'min',
        limit: Number(env.BING_RATE_LIMIT) > 0 ? Math.floor(Number(env.BING_RATE_LIMIT)) : 30,
        windowSec: 60,
      },
    ],
    kv: env?.RATE_LIMIT_KV || null,
  });
  if (limited) return limited;

  let images = [];

  try {
    const res = await fetch(BING_URL, {
      headers: { accept: 'application/json' },
      signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout
        ? AbortSignal.timeout(8000)
        : undefined,
      // Bing 每天只换一次图，缓存 1 小时足够，省下大量回源
      cf: { cacheEverything: true, cacheTtl: 3600 },
    });

    if (res.ok) {
      const data = await res.json();
      images = Array.isArray(data?.images) ? data.images : [];
    } else {
      console.error('wallpaper: bing 返回', res.status);
    }
  } catch (error) {
    console.error('wallpaper: 回源失败', error?.message || error);
  }

  return jsonResponse(
    {
      status: images.length > 0,
      message: images.length ? '操作成功' : '壁纸暂不可用',
      data: images,
    },
    200,
    { 'Cache-Control': 'public, max-age=1800' }
  );
}
