/**
 * Cloudflare Pages 全站访问密码 - 中间件
 *
 * 放置位置：你 fork 的 Rin 仓库根目录下的 functions/_middleware.js
 *             （即和 client、server 文件夹同级，不是放在 client/dist 里）
 * 依赖环境变量：CFP_PASSWORD（必填）—— 站点访问密码，在 Pages 项目设置里添加
 *
 * 作用：对站点所有页面与静态资源统一做密码校验。
 *      未通过校验的访客只能看到一个密码输入页，输入正确密码后 7 天内免重复输入。
 */

const COOKIE_NAME = 'rin_site_auth';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 通过后 7 天免重复输入

/** 生成与密码绑定的校验令牌，避免把明文密码写进 Cookie */
async function makeToken(password) {
  const data = new TextEncoder().encode('rin::site::' + password);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map(function (b) {
      return b.toString(16).padStart(2, '0');
    })
    .join('');
}

/** 从请求头里读取指定 Cookie */
function readCookie(request) {
  const raw = request.headers.get('Cookie') || '';
  const match = raw.match(new RegExp('(?:^|;\\s*)' + COOKIE_NAME + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

/** 转义 HTML 属性值 */
function escapeAttr(text) {
  return String(text).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

/** 登录页 HTML（内联样式，不依赖任何外部资源，保证未登录时也能正常渲染） */
function loginPage(errorMsg, redirectPath) {
  const safeRedirect = escapeAttr(redirectPath || '/');
  const html = [
    '<!DOCTYPE html>',
    '<html lang="zh-CN">',
    '<head>',
    '<meta charset="utf-8" />',
    '<meta name="viewport" content="width=device-width, initial-scale=1" />',
    '<title>请输入访问密码</title>',
    '<style>',
    '  * { box-sizing: border-box; }',
    '  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;',
    '    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;',
    '    background: #f3f4f6; color: #111; padding: 20px; }',
    '  .box { width: 100%; max-width: 380px; padding: 36px 28px; background: #fff;',
    '    border: 1px solid #e5e7eb; border-radius: 16px; box-shadow: 0 8px 30px rgba(0,0,0,.08); text-align: center; }',
    '  .icon { font-size: 44px; }',
    '  h1 { font-size: 18px; margin: 14px 0 6px; }',
    '  p { font-size: 13px; color: #6b7280; margin: 0 0 22px; }',
    '  input { width: 100%; padding: 12px 14px; font-size: 15px; border: 1px solid #d1d5db;',
    '    border-radius: 10px; outline: none; text-align: center; letter-spacing: 2px; }',
    '  input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,.15); }',
    '  button { width: 100%; margin-top: 14px; padding: 12px; font-size: 15px; color: #fff;',
    '    background: #3b82f6; border: none; border-radius: 10px; cursor: pointer; }',
    '  button:hover { background: #2563eb; }',
    '  .err { margin-top: 12px; font-size: 13px; color: #ef4444; min-height: 18px; }',
    '  @media (prefers-color-scheme: dark) {',
    '    body { background: #0f172a; color: #e5e7eb; }',
    '    .box { background: #1f2937; border-color: #374151; }',
    '    p { color: #9ca3af; }',
    '    input { background: #111827; color: #e5e7eb; border-color: #374151; }',
    '  }',
    '</style>',
    '</head>',
    '<body>',
    '  <form class="box" method="POST" action="/__auth_login">',
    '    <div class="icon">&#128274;</div>',
    '    <h1>此站点已加密</h1>',
    '    <p>请输入访问密码以继续访问</p>',
    '    <input type="password" name="password" placeholder="访问密码" autofocus autocomplete="current-password" />',
    '    <input type="hidden" name="redirect" value="' + safeRedirect + '" />',
    '    <button type="submit">进入站点</button>',
    '    <div class="err">' + errorMsg + '</div>',
    '  </form>',
    '</body>',
    '</html>',
  ].join('\n');

  return new Response(html, {
    status: 401,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);
  const password = env.CFP_PASSWORD;

  // 未配置密码时明确报错，避免误配置导致站点裸奔
  if (!password) {
    return new Response('站点未配置访问密码：请在 Cloudflare Pages 项目设置中添加环境变量 CFP_PASSWORD 后重新部署。', {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }

  const token = await makeToken(password);

  // 退出登录
  if (url.pathname === '/__auth_logout') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: '/',
        'Set-Cookie': COOKIE_NAME + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
      },
    });
  }

  // 提交密码
  if (url.pathname === '/__auth_login' && request.method === 'POST') {
    const form = await request.formData();
    const input = String(form.get('password') || '');
    const redirect = String(form.get('redirect') || '/');
    if (input === password) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: redirect.charAt(0) === '/' ? redirect : '/',
          'Set-Cookie':
            COOKIE_NAME + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + COOKIE_MAX_AGE,
        },
      });
    }
    return loginPage('密码错误，请重试', redirect);
  }

  // 已通过校验，放行
  if (readCookie(request) === token) {
    return next();
  }

  // 未通过校验，返回登录页
  return loginPage('', url.pathname + url.search);
}
