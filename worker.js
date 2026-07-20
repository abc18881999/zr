/**
 * ZR 游戏平台 — Cloudflare Worker 后端
 *
 * KV 绑定名称: PLAYERS
 * KV 数据结构:
 *   player:{username}  → { username, pass_hash, tg_num, tg_user, tg_id, balance, created_at, last_login }
 *   players_index      → ["user1", "user2", ...]
 *   session:{token}    → { username, expires }
 *   admin_token:{token}→ { expires }
 *   admin_config       → { pass_hash }
 *
 * 默认管理员密码: admin888  （第一次使用后请在后台修改）
 */

const SALT = 'zr_platform_2026';
const DEFAULT_ADMIN_PASS = 'admin888';
const SESSION_TTL_SEC = 7 * 24 * 3600;   // 玩家 session 7天
const ADMIN_TTL_SEC   = 24 * 3600;        // 管理员 token 24小时
const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
    async fetch(request, env) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: CORS });
        }
        const url = new URL(request.url);
        if (url.pathname.startsWith('/api/')) {
            return withCors(await handleAPI(request, env, url.pathname));
        }
        return env.ASSETS.fetch(request);
    }
};

// ─── 路由 ────────────────────────────────────────────────────────────────────

async function handleAPI(req, env, path) {
    const method = req.method;

    // 玩家注册 / 登录
    if (path === '/api/auth' && method === 'POST')
        return authHandler(req, env);

    // 玩家信息（需要登录 token）
    if (path === '/api/player/info' && method === 'GET')
        return playerInfo(req, env);

    // 玩家余额同步（游戏结束后上报）
    if (path === '/api/player/sync-balance' && method === 'POST')
        return syncBalance(req, env);

    // 管理员登录
    if (path === '/api/admin/login' && method === 'POST')
        return adminLogin(req, env);

    // 管理员接口（均需管理员 token）
    if (path.startsWith('/api/admin/')) {
        const ok = await verifyAdminToken(req, env);
        if (!ok) return jsonRes({ error: '管理员认证失败，请重新登录' }, 401);

        if (path === '/api/admin/players'  && method === 'GET')  return adminListPlayers(env);
        if (path === '/api/admin/player'   && method === 'GET')  return adminGetPlayer(req, env);
        if (path === '/api/admin/balance'  && method === 'POST') return adminSetBalance(req, env);
        if (path === '/api/admin/delete'   && method === 'POST') return adminDeletePlayer(req, env);
        if (path === '/api/admin/set-pass' && method === 'POST') return adminChangePass(req, env);
    }

    return jsonRes({ error: '接口不存在' }, 404);
}

// ─── 玩家注册 / 登录 ─────────────────────────────────────────────────────────

async function authHandler(req, env) {
    const body = await req.json().catch(() => null);
    if (!body) return jsonRes({ error: '请求格式错误' }, 400);

    const { type, user, pass, tg_num, tg_user, tg_id } = body;

    if (!user || !pass) return jsonRes({ error: '账号和密码不能为空' }, 400);
    if (!/^[a-zA-Z0-9_]{4,20}$/.test(user))
        return jsonRes({ error: '账号只能含字母、数字、下划线，4-20位' }, 400);
    if (pass.length < 6)
        return jsonRes({ error: '密码至少6位' }, 400);

    if (type === 'register') {
        if (!tg_num || !tg_user || !tg_id)
            return jsonRes({ error: '注册需填写全部 Telegram 信息' }, 400);

        const exists = await env.PLAYERS.get('player:' + user);
        if (exists) return jsonRes({ error: '账号已存在，请直接登录' }, 409);

        const player = {
            username:   user,
            pass_hash:  await hashPass(pass),
            tg_num,
            tg_user,
            tg_id,
            balance:    10000,
            created_at: new Date().toISOString(),
            last_login: new Date().toISOString(),
        };
        await env.PLAYERS.put('player:' + user, JSON.stringify(player));
        await addToIndex(env, user);
        return jsonRes({ ok: true, message: '注册成功，请登录' }, 201);

    } else if (type === 'login') {
        const raw = await env.PLAYERS.get('player:' + user);
        if (!raw) return jsonRes({ error: '账号不存在' }, 404);

        const player = JSON.parse(raw);
        if (player.pass_hash !== await hashPass(pass))
            return jsonRes({ error: '密码错误' }, 401);

        // 更新最后登录时间
        player.last_login = new Date().toISOString();
        await env.PLAYERS.put('player:' + user, JSON.stringify(player));

        const token = await genToken();
        const expires = Date.now() + SESSION_TTL_SEC * 1000;
        await env.PLAYERS.put('session:' + token, JSON.stringify({ username: user, expires }),
            { expirationTtl: SESSION_TTL_SEC });

        return jsonRes({
            ok: true,
            token,
            player: safePlayerData(player)
        });
    }

    return jsonRes({ error: '未知操作类型' }, 400);
}

// ─── 玩家信息 ─────────────────────────────────────────────────────────────────

async function playerInfo(req, env) {
    const { username, error } = await verifySessionToken(req, env);
    if (error) return jsonRes({ error }, 401);

    const raw = await env.PLAYERS.get('player:' + username);
    if (!raw) return jsonRes({ error: '玩家不存在' }, 404);

    return jsonRes(safePlayerData(JSON.parse(raw)));
}

// ─── 余额同步（游戏结束后由前端上报）────────────────────────────────────────

async function syncBalance(req, env) {
    const { username, error } = await verifySessionToken(req, env);
    if (error) return jsonRes({ error }, 401);

    const body = await req.json().catch(() => null);
    if (!body || typeof body.balance !== 'number')
        return jsonRes({ error: '参数错误' }, 400);

    const raw = await env.PLAYERS.get('player:' + username);
    if (!raw) return jsonRes({ error: '玩家不存在' }, 404);

    const player = JSON.parse(raw);
    player.balance = Math.max(0, Math.round(body.balance));
    await env.PLAYERS.put('player:' + username, JSON.stringify(player));

    return jsonRes({ ok: true, balance: player.balance });
}

// ─── 管理员登录 ───────────────────────────────────────────────────────────────

async function adminLogin(req, env) {
    const body = await req.json().catch(() => null);
    if (!body || !body.pass) return jsonRes({ error: '请输入管理员密码' }, 400);

    const configRaw = await env.PLAYERS.get('admin_config');
    let config = configRaw ? JSON.parse(configRaw) : null;

    // 首次使用：初始化默认管理员密码
    if (!config) {
        config = { pass_hash: await hashPass(DEFAULT_ADMIN_PASS) };
        await env.PLAYERS.put('admin_config', JSON.stringify(config));
    }

    if (config.pass_hash !== await hashPass(body.pass))
        return jsonRes({ error: '管理员密码错误' }, 401);

    const token = await genToken();
    await env.PLAYERS.put('admin_token:' + token, JSON.stringify({ expires: Date.now() + ADMIN_TTL_SEC * 1000 }),
        { expirationTtl: ADMIN_TTL_SEC });

    return jsonRes({ ok: true, token });
}

// ─── 管理员：玩家列表 ─────────────────────────────────────────────────────────

async function adminListPlayers(env) {
    const indexRaw = await env.PLAYERS.get('players_index');
    const index = indexRaw ? JSON.parse(indexRaw) : [];

    const players = await Promise.all(
        index.map(async u => {
            const raw = await env.PLAYERS.get('player:' + u);
            return raw ? safePlayerData(JSON.parse(raw), true) : null;
        })
    );

    return jsonRes({ players: players.filter(Boolean) });
}

// ─── 管理员：查看单个玩家 ─────────────────────────────────────────────────────

async function adminGetPlayer(req, env) {
    const url = new URL(req.url);
    const username = url.searchParams.get('user');
    if (!username) return jsonRes({ error: '缺少 user 参数' }, 400);

    const raw = await env.PLAYERS.get('player:' + username);
    if (!raw) return jsonRes({ error: '玩家不存在' }, 404);

    return jsonRes(safePlayerData(JSON.parse(raw), true));
}

// ─── 管理员：修改余额 ─────────────────────────────────────────────────────────

async function adminSetBalance(req, env) {
    const body = await req.json().catch(() => null);
    if (!body || !body.username || typeof body.balance !== 'number')
        return jsonRes({ error: '参数错误' }, 400);

    const raw = await env.PLAYERS.get('player:' + body.username);
    if (!raw) return jsonRes({ error: '玩家不存在' }, 404);

    const player = JSON.parse(raw);
    player.balance = Math.max(0, Math.round(body.balance));
    await env.PLAYERS.put('player:' + body.username, JSON.stringify(player));

    return jsonRes({ ok: true, username: body.username, balance: player.balance });
}

// ─── 管理员：删除玩家 ─────────────────────────────────────────────────────────

async function adminDeletePlayer(req, env) {
    const body = await req.json().catch(() => null);
    if (!body || !body.username) return jsonRes({ error: '参数错误' }, 400);

    await env.PLAYERS.delete('player:' + body.username);
    await removeFromIndex(env, body.username);

    return jsonRes({ ok: true });
}

// ─── 管理员：修改管理员密码 ───────────────────────────────────────────────────

async function adminChangePass(req, env) {
    const body = await req.json().catch(() => null);
    if (!body || !body.new_pass || body.new_pass.length < 6)
        return jsonRes({ error: '新密码至少6位' }, 400);

    await env.PLAYERS.put('admin_config', JSON.stringify({
        pass_hash: await hashPass(body.new_pass)
    }));

    return jsonRes({ ok: true, message: '管理员密码已更新' });
}

// ─── 工具函数 ─────────────────────────────────────────────────────────────────

async function hashPass(password) {
    const enc = new TextEncoder();
    const data = enc.encode(password + SALT);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function genToken() {
    return crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
}

async function verifySessionToken(req, env) {
    const auth = req.headers.get('Authorization') || '';
    const token = auth.replace('Bearer ', '').trim();
    if (!token) return { error: '未提供 token' };

    const raw = await env.PLAYERS.get('session:' + token);
    if (!raw) return { error: 'token 无效或已过期' };

    const session = JSON.parse(raw);
    if (Date.now() > session.expires) return { error: 'token 已过期' };

    return { username: session.username };
}

async function verifyAdminToken(req, env) {
    const auth = req.headers.get('Authorization') || '';
    const token = auth.replace('Bearer ', '').trim();
    if (!token) return false;

    const raw = await env.PLAYERS.get('admin_token:' + token);
    if (!raw) return false;

    const t = JSON.parse(raw);
    return Date.now() <= t.expires;
}

function safePlayerData(p, isAdmin = false) {
    const base = {
        username:   p.username,
        tg_user:    p.tg_user,
        balance:    p.balance,
        created_at: p.created_at,
        last_login: p.last_login,
    };
    if (isAdmin) {
        base.tg_num = p.tg_num;
        base.tg_id  = p.tg_id;
    }
    return base;
}

async function addToIndex(env, username) {
    const raw = await env.PLAYERS.get('players_index');
    const index = raw ? JSON.parse(raw) : [];
    if (!index.includes(username)) {
        index.push(username);
        await env.PLAYERS.put('players_index', JSON.stringify(index));
    }
}

async function removeFromIndex(env, username) {
    const raw = await env.PLAYERS.get('players_index');
    if (!raw) return;
    const index = JSON.parse(raw).filter(u => u !== username);
    await env.PLAYERS.put('players_index', JSON.stringify(index));
}

function jsonRes(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

function withCors(response) {
    const headers = new Headers(response.headers);
    Object.entries(CORS).forEach(([k, v]) => headers.set(k, v));
    return new Response(response.body, { status: response.status, headers });
}
