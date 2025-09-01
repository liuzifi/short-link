/**
 * Welcome to Cloudflare Workers!
 *
 * This is a complete script for a URL shortener with an admin panel.
 *
 * - Public can create short links.
 * - Admin can log in at /admin to manage all links.
 * - Uses D1 for storage.
 * - Uses plain password and JWT for auth.
 *
 * Setup:
 * 1. Create a D1 database and run the schema below:
 *    CREATE TABLE links (slug TEXT PRIMARY KEY, url TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
 * 2. In Worker settings -> Variables:
 *    - Add D1 binding: Name: DB, Namespace: your-d1-database
 *    - Add Env Var: Name: ADMIN_PASSWORD, Value: your-secret-password
 *    - Add Env Var: Name: JWT_SECRET, Value: your-long-random-jwt-secret
 */

// A tiny JWT library for generating and verifying tokens.
// No external dependencies needed.
const jwt = {
    // Base64URL encode
    _b64UrlEncode: (str) => btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
    // Base64URL decode
    _b64UrlDecode: (str) => atob(str.replace(/-/g, '+').replace(/_/g, '/')),

    // Create a JWT
    async sign(payload, secret) {
        const header = { alg: 'HS256', typ: 'JWT' };
        const encodedHeader = this._b64UrlEncode(JSON.stringify(header));
        const encodedPayload = this._b64UrlEncode(JSON.stringify(payload));
        const signatureInput = `${encodedHeader}.${encodedPayload}`;

        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signatureInput));
        const encodedSignature = this._b64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));

        return `${signatureInput}.${encodedSignature}`;
    },

    // Verify a JWT
    async verify(token, secret) {
        try {
            const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
            const signatureInput = `${encodedHeader}.${encodedPayload}`;

            const key = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(secret),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['verify']
            );
            const signature = new Uint8Array(
                this._b64UrlDecode(encodedSignature)
                    .split('')
                    .map((c) => c.charCodeAt(0))
            );

            const isValid = await crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(signatureInput));
            if (!isValid) return null;

            const payload = JSON.parse(this._b64UrlDecode(encodedPayload));
            // Check expiration
            if (payload.exp && payload.exp < Date.now() / 1000) {
                return null;
            }
            return payload;
        } catch (e) {
            return null;
        }
    },
};


export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // Main Router
        try {
            // Admin Panel HTML
            if (url.pathname === '/admin') {
                return new Response(getAdminHTML(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
            // Admin API: Login
            if (url.pathname === '/api/admin/login' && request.method === 'POST') {
                return await handleAdminLogin(request, env);
            }
            // Admin API: Manage Links (protected)
            if (url.pathname.startsWith('/api/admin/links')) {
                return await handleAdminLinks(request, env);
            }
            // Public API: Create Link
            if (url.pathname === '/' && request.method === 'POST') {
                return await handleCreateLink(request, env);
            }
            // Public View: Home Page
            if (url.pathname === '/') {
                return new Response(getPublicHTML(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
            // Redirect Logic
            return await handleRedirect(request, env);

        } catch (e) {
            return new Response(e.message || 'Server Error', { status: 500 });
        }
    },
};

/**
 * Handles admin login.
 * Compares plain password and issues a JWT.
 */
async function handleAdminLogin(request, env) {
    const { password } = await request.json();

    if (!password || password !== env.ADMIN_PASSWORD) {
        return new Response('Invalid credentials', { status: 401 });
    }

    // Password is correct, issue a JWT valid for 8 hours
    const token = await jwt.sign({
        // 'iat' (issued at) and 'exp' (expiration time) are standard JWT claims
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60, // 8 hours
    }, env.JWT_SECRET);

    return new Response(JSON.stringify({ token }), { headers: { 'Content-Type': 'application/json' } });
}

/**
 * Handles all CRUD operations for links by the admin.
 * All routes here are protected by JWT.
 */
async function handleAdminLinks(request, env) {
    // --- Authentication Check ---
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response('Unauthorized', { status: 401 });
    }
    const token = authHeader.substring(7);
    const payload = await jwt.verify(token, env.JWT_SECRET);
    if (!payload) {
        return new Response('Invalid or expired token', { status: 403 });
    }
    // --- End Authentication Check ---

    const url = new URL(request.url);
    const slug = url.pathname.split('/')[4]; // /api/admin/links/{slug}

    // GET /api/admin/links - List all links
    if (request.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT slug, url, created_at FROM links ORDER BY created_at DESC').all();
        return new Response(JSON.stringify(results), { headers: { 'Content-Type': 'application/json' } });
    }

    // DELETE /api/admin/links/{slug} - Delete a link
    if (request.method === 'DELETE' && slug) {
        await env.DB.prepare('DELETE FROM links WHERE slug = ?').bind(slug).run();
        return new Response('Link deleted', { status: 200 });
    }
    
    // PUT /api/admin/links/{slug} - Update a link
    if (request.method === 'PUT' && slug) {
        const { url: newUrl } = await request.json();
        if (!newUrl || !newUrl.startsWith('http' )) {
            return new Response('Invalid URL format', { status: 400 });
        }
        await env.DB.prepare('UPDATE links SET url = ? WHERE slug = ?').bind(newUrl, slug).run();
        return new Response('Link updated', { status: 200 });
    }

    return new Response('Invalid admin API request', { status: 400 });
}

/**
 * Handles public creation of a new short link.
 */
async function handleCreateLink(request, env) {
    const { url, slug } = await request.json();

    if (!url || !url.startsWith('http' )) {
        return new Response('Invalid URL format. It must start with http or https.', { status: 400 } );
    }

    let finalSlug = slug;
    if (!finalSlug) {
        // Generate a random 4-char slug if not provided
        finalSlug = Math.random().toString(36).substring(2, 6);
    }

    try {
        await env.DB.prepare('INSERT INTO links (slug, url) VALUES (?, ?)')
            .bind(finalSlug, url)
            .run();
        return new Response(JSON.stringify({ slug: finalSlug }), { status: 201, headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
        // Check for unique constraint violation
        if (e.message.includes('UNIQUE constraint failed')) {
            return new Response(`Slug "${finalSlug}" is already taken.`, { status: 409 });
        }
        return new Response('Database error', { status: 500 });
    }
}

/**
 * Handles redirecting a short link to its destination.
 */
async function handleRedirect(request, env) {
    const slug = new URL(request.url).pathname.substring(1);
    if (!slug) {
        return new Response('Not Found', { status: 404 });
    }

    const result = await env.DB.prepare('SELECT url FROM links WHERE slug = ?').bind(slug).first();

    if (result && result.url) {
        return Response.redirect(result.url, 302);
    }

    return new Response(`Slug "${slug}" not found.`, { status: 404 });
}


// --- HTML Templates ---

function getPublicHTML() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Shortener</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin: 0; }
        .container { background: white; padding: 3rem; border-radius: 12px; box-shadow: 0 6px 16px rgba(0,0,0,0.15); text-align: center; }
        .input-group { display: flex; flex-direction: column; align-items: center; }
        input { width: 350px; padding: 0.75rem; margin-bottom: 1.5rem; border: 2px solid #ccc; border-radius: 6px; font-size: 1.1rem; }
        button { padding: 0.75rem 1.5rem; border: none; background: #007bff; color: white; border-radius: 6px; cursor: pointer; width: 350px; font-size: 1.1rem; font-weight: bold; }
        #result { margin-top: 1.5rem; font-weight: bold; font-size: 1.2rem; }
        a { color: #007bff; font-size: 1.1rem; }
        h1 { font-size: 2rem; margin-bottom: 1.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Create a Short Link</h1>
        <div class="input-group">
            <input type="url" id="urlInput" placeholder="Enter long URL here (e.g., https://... )" required>
            <input type="text" id="slugInput" placeholder="Optional: custom slug">
            <button onclick="createLink()">Shorten</button>
        </div>
        <p id="result"></p>
        <p><a href="/admin">Admin Login</a></p>
    </div>
    <script>
        async function createLink() {
            const url = document.getElementById('urlInput').value;
            const slug = document.getElementById('slugInput').value;
            const resultEl = document.getElementById('result');
            
            if (!url) {
                resultEl.textContent = 'Please enter a URL.';
                return;
            }

            const response = await fetch('/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, slug: slug || undefined })
            });

            if (response.ok) {
                const data = await response.json();
                const shortUrl = window.location.origin + '/' + data.slug;
                resultEl.innerHTML = \`Success! Your short link is: <a href="\${shortUrl}" target="_blank">\${shortUrl}</a>\`;
                
                // Auto copy to clipboard
                try {
                    await navigator.clipboard.writeText(shortUrl);
                    resultEl.innerHTML += '<br><span style="color: green;">(Copied to clipboard!)</span>';
                } catch (err) {
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = shortUrl;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    resultEl.innerHTML += '<br><span style="color: green;">(Copied to clipboard!)</span>';
                }
            } else {
                resultEl.textContent = 'Error: ' + await response.text();
            }
        }
    </script>
</body>
</html>
    `;
}

function getAdminHTML() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; margin: 2rem; }
        .container { max-width: 900px; margin: auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        #login-view, #dashboard-view { text-align: center; }
        #dashboard-view { display: none; }
        input { padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 0.5rem 1rem; border: none; background: #007bff; color: white; border-radius: 4px; cursor: pointer; }
        .btn-danger { background: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 2rem; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        td .actions button { margin-right: 5px; padding: 0.25rem 0.5rem; }
        .url-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        
        /* Mobile responsive styles */
        @media (max-width: 768px) {
            body { margin: 1rem; padding: 0; }
            .container { padding: 1rem; }
            table { font-size: 0.9rem; }
            th, td { padding: 0.5rem; }
            .url-cell { max-width: 150px; }
        }
        
        @media (max-width: 480px) {
            body { margin: 0.5rem; }
            .container { padding: 0.5rem; }
            table { font-size: 0.8rem; }
            th, td { padding: 0.4rem; }
            .url-cell { max-width: 100px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login View -->
        <div id="login-view">
            <h1>Admin Login</h1>
            <input type="password" id="password" placeholder="Enter password">
            <button onclick="login()">Login</button>
            <p id="login-error" style="color: red;"></p>
        </div>

        <!-- Dashboard View -->
        <div id="dashboard-view">
            <h1>Link Management</h1>
            <button onclick="logout()">Logout</button>
            <table id="links-table">
                <thead>
                    <tr>
                        <th>Slug</th>
                        <th>Destination URL</th>
                        <th>Created At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Rows will be inserted here -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const loginView = document.getElementById('login-view');
        const dashboardView = document.getElementById('dashboard-view');
        const tokenKey = 'admin-token';

        // --- Auth Logic ---
        async function login() {
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('login-error');
            errorEl.textContent = '';

            const response = await fetch('/api/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });

            if (response.ok) {
                const { token } = await response.json();
                localStorage.setItem(tokenKey, token);
                showDashboard();
            } else {
                errorEl.textContent = 'Login failed. Please try again.';
            }
        }

        function logout() {
            localStorage.removeItem(tokenKey);
            loginView.style.display = 'block';
            dashboardView.style.display = 'none';
        }

        // --- Dashboard Logic ---
        async function showDashboard() {
            const token = localStorage.getItem(tokenKey);
            if (!token) {
                loginView.style.display = 'block';
                dashboardView.style.display = 'none';
                return;
            }
            
            loginView.style.display = 'none';
            dashboardView.style.display = 'block';
            await loadLinks(token);
        }

        async function loadLinks(token) {
            const response = await fetch('/api/admin/links', {
                headers: { 'Authorization': \`Bearer \${token}\` }
            });

            if (!response.ok) {
                alert('Session expired. Please log in again.');
                logout();
                return;
            }

            const links = await response.json();
            const tbody = document.querySelector('#links-table tbody');
            tbody.innerHTML = ''; // Clear existing rows

            links.forEach(link => {
                const row = document.createElement('tr');
                row.innerHTML = \`
                    <td><a href="/\${link.slug}" target="_blank">/\${link.slug}</a></td>
                    <td class="url-cell" title="\${link.url}"><a href="\${link.url}" target="_blank">\${link.url}</a></td>
                    <td>\${new Date(link.created_at).toLocaleString()}</td>
                    <td class="actions">
                        <button onclick="editLink('\${link.slug}')">Edit</button>
                        <button class="btn-danger" onclick="deleteLink('\${link.slug}')">Delete</button>
                    </td>
                \` ;
                tbody.appendChild(row);
            });
        }

        async function deleteLink(slug) {
            if (!confirm(\`Are you sure you want to delete the link "/\${slug}"?\`)) return;

            const token = localStorage.getItem(tokenKey);
            const response = await fetch(\`/api/admin/links/\${slug}\`, {
                method: 'DELETE',
                headers: { 'Authorization': \`Bearer \${token}\` }
            });

            if (response.ok) {
                await loadLinks(token);
            } else {
                alert('Failed to delete link.');
            }
        }
        
        async function editLink(slug) {
            const newUrl = prompt(\`Enter the new destination URL for "/\${slug}":\`);
            if (!newUrl || !newUrl.startsWith('http' )) {
                alert('Invalid URL. It must start with http or https.' );
                return;
            }

            const token = localStorage.getItem(tokenKey);
            const response = await fetch(\`/api/admin/links/\${slug}\`, {
                method: 'PUT',
                headers: { 
                    'Authorization': \`Bearer \${token}\`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: newUrl })
            });

            if (response.ok) {
                await loadLinks(token);
            } else {
                alert('Failed to update link.');
            }
        }

        // Initial load
        document.addEventListener('DOMContentLoaded', showDashboard);
    </script>
</body>
</html>
    `;
}
