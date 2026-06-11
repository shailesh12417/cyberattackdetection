const API_BASE = window.location.protocol === "file:" ? "http://127.0.0.1:8000" : "";
const TOKEN_KEY = 'cyberguard_token';

function showToast(message, type = 'info') {
  const toast = document.getElementById('authToast');
  toast.textContent = message;
  toast.className = `show ${type}`;
  setTimeout(() => {
    toast.className = '';
  }, 3000);
}

function switchView(view) {
  document.getElementById('loginForm').classList.add('hidden');
  document.getElementById('signupForm').classList.add('hidden');
  document.getElementById('resetForm').classList.add('hidden');
  
  if (view === 'login') {
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('authTitle').textContent = 'Sign In';
    document.getElementById('authSubtitle').textContent = 'Access your CyberGuard dashboard';
  } else if (view === 'signup') {
    document.getElementById('signupForm').classList.remove('hidden');
    document.getElementById('authTitle').textContent = 'Create Account';
    document.getElementById('authSubtitle').textContent = 'Join CyberGuard platform';
  } else if (view === 'reset') {
    document.getElementById('resetForm').classList.remove('hidden');
    document.getElementById('authTitle').textContent = 'Reset Password';
    document.getElementById('authSubtitle').textContent = 'Recover your account access';
  }
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginPassword').value;
  
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Login failed');
    
    localStorage.setItem(TOKEN_KEY, data.access_token);
    showToast('Login successful!', 'success');
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1000);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleSignup(e) {
  e.preventDefault();
  const username = document.getElementById('signupUsername').value;
  const password = document.getElementById('signupPassword').value;
  const security_phrase = document.getElementById('signupPhrase').value;
  
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, security_phrase })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Signup failed');
    
    localStorage.setItem(TOKEN_KEY, data.access_token);
    showToast('Account created!', 'success');
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1000);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleReset(e) {
  e.preventDefault();
  const username = document.getElementById('resetUsername').value;
  const security_phrase = document.getElementById('resetPhrase').value;
  const new_password = document.getElementById('resetNewPassword').value;
  
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, security_phrase, new_password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Reset failed');
    
    showToast('Password reset successful. Please login.', 'success');
    setTimeout(() => {
      switchView('login');
    }, 1500);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function hasValidSession() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return false;

  try {
    const response = await fetch(`${API_BASE}/api/v1/health`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (response.ok) return true;
  } catch (err) {
    return false;
  }

  localStorage.removeItem(TOKEN_KEY);
  return false;
}

hasValidSession().then((valid) => {
  if (valid) window.location.href = 'index.html';
});
