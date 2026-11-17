// Login y registro con Google y GitHub (sin librerías nuevas: usa fetch de Node)
// Flujo: React -> /api/auth/google -> Google -> /api/auth/google/callback -> React /auth/callback?token=...
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const db     = require('../config/db');

const FRONT = () => (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
const BACK  = () => (process.env.BACKEND_URL  || 'http://localhost:4000').replace(/\/$/, '');

const firmar = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });

// "state" firmado: protege contra CSRF sin guardar nada en el servidor
const crearState = () => jwt.sign({ n: crypto.randomBytes(8).toString('hex') }, process.env.JWT_SECRET, { expiresIn: '10m' });
const validarState = (s) => { try { jwt.verify(s, process.env.JWT_SECRET); return true; } catch { return false; } };

const volverConError = (res, msg) =>
  res.redirect(`${FRONT()}/login?error=${encodeURIComponent(msg)}`);

// Busca el usuario por email; si no existe lo crea (así sirve para login Y registro)
const loginOCrearUsuario = async (nombre, email) => {
  const [rows] = await db.query('SELECT id, email FROM usuarios WHERE email = ?', [email]);
  let user = rows[0];
  if (!user) {
    // Contraseña aleatoria: la cuenta social no tiene contraseña usable, pero la columna queda válida
    const hash = await bcrypt.hash(crypto.randomBytes(24).toString('hex'), 10);
    const [r] = await db.query(
      'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)',
      [nombre || email.split('@')[0], email, hash]
    );
    user = { id: r.insertId, email };
  }
  return firmar({ id: user.id, email: user.email, tipo: 'usuario', rol: 'usuario' });
};

// ───────── Google ─────────
const googleInicio = (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: `${BACK()}/api/auth/google/callback`,
    response_type: 'code',
    scope: 'openid email profile',
    state: crearState(),
    prompt: 'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
};

const googleCallback = async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !validarState(state)) return volverConError(res, 'Solicitud inválida');

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${BACK()}/api/auth/google/callback`,
        grant_type: 'authorization_code',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return volverConError(res, 'Google no autorizó el acceso');

    const perfil = await (await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    })).json();

    if (!perfil.email || !perfil.email_verified) return volverConError(res, 'Tu correo de Google no está verificado');

    const token = await loginOCrearUsuario(perfil.name, perfil.email);
    res.redirect(`${FRONT()}/auth/callback?token=${token}`);
  } catch (e) {
    console.error(e);
    volverConError(res, 'Error al iniciar sesión con Google');
  }
};

// ───────── GitHub ─────────
const githubInicio = (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: `${BACK()}/api/auth/github/callback`,
    scope: 'user:email',
    state: crearState(),
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
};

const githubCallback = async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !validarState(state)) return volverConError(res, 'Solicitud inválida');

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${BACK()}/api/auth/github/callback`,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return volverConError(res, 'GitHub no autorizó el acceso');

    const headers = {
      Authorization: `Bearer ${tokenData.access_token}`,
      'User-Agent': 'taller-masc',
      Accept: 'application/vnd.github+json',
    };
    const perfil = await (await fetch('https://api.github.com/user', { headers })).json();

    // El email de GitHub puede ser privado: se pide la lista de correos y se toma el principal verificado
    const emails = await (await fetch('https://api.github.com/user/emails', { headers })).json();
    const principal = Array.isArray(emails) ? emails.find(e => e.primary && e.verified) : null;
    const email = principal?.email;
    if (!email) return volverConError(res, 'Tu cuenta de GitHub no tiene un correo verificado');

    const token = await loginOCrearUsuario(perfil.name || perfil.login, email);
    res.redirect(`${FRONT()}/auth/callback?token=${token}`);
  } catch (e) {
    console.error(e);
    volverConError(res, 'Error al iniciar sesión con GitHub');
  }
};

module.exports = { googleInicio, googleCallback, githubInicio, githubCallback };
