const router = require('express').Router();
const { login, register } = require('../controllers/authController');
const oauth = require('../controllers/oauthController');

router.post('/register', register);
router.post('/login',    login);

// Login / registro con Google y GitHub
router.get('/google',          oauth.googleInicio);
router.get('/google/callback', oauth.googleCallback);
router.get('/github',          oauth.githubInicio);
router.get('/github/callback', oauth.githubCallback);

module.exports = router;
