import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

// Página a la que el backend devuelve al usuario tras entrar con Google o GitHub.
// Ruta sugerida: /auth/callback
export default function OAuthCallback() {
  const navigate = useNavigate();

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('token');
    if (token) {
      // IMPORTANTE: usa la MISMA clave que tu Login.jsx al guardar el token
      localStorage.setItem('token', token);
      // Recarga completa para que tu AuthContext lea el token guardado
      window.location.replace('/');
    } else {
      navigate('/login?error=No se recibió el token');
    }
  }, [navigate]);

  return <p>Iniciando sesión...</p>;
}

/* ─────────────────────────────────────────────
   Botones para pegar en Login.jsx y Register.jsx
   ─────────────────────────────────────────────

const API = import.meta.env.VITE_API_URL || 'http://localhost:4000/api';

<a href={`${API}/auth/google`}><button type="button">Continuar con Google</button></a>
<a href={`${API}/auth/github`}><button type="button">Continuar con GitHub</button></a>

   Y en tu router (main.jsx o App.jsx) agrega:

<Route path="/auth/callback" element={<OAuthCallback />} />
*/
