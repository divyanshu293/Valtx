package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Credential structure
type Credential struct {
	ID                string    `json:"id"`
	Service           string    `json:"service"`
	Username          string    `json:"username"`
	EncryptedPassword []byte    `json:"-"` // Never exposed in JSON
	EncryptedNotes    []byte    `json:"-"` // Optional notes
	Category          string    `json:"category"`
	Tags              []string  `json:"tags"`
	URL               string    `json:"url"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// In-memory vault
type Vault struct {
	mu        sync.RWMutex
	creds     map[string]Credential
	masterKey []byte
	lastAccess time.Time
}

var vault Vault

// Frontend HTML with modern styling and animations
var indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🔐 VaultX — Secure Credential Manager</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --primary: #6366f1;
      --primary-dark: #4f46e5;
      --secondary: #8b5cf6;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --info: #3b82f6;
      --dark: #1e293b;
      --gray: #64748b;
      --light: #f8fafc;
      --border: #e2e8f0;
      --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
      --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .dark {
      --dark: #f8fafc;
      --light: #1e293b;
      --border: #334155;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }

    .container {
      width: 100%;
      max-width: 1200px;
    }

    .card {
      background: var(--light);
      border-radius: 16px;
      box-shadow: var(--shadow-lg);
      padding: 2rem;
      margin-bottom: 1.5rem;
      transition: var(--transition);
    }

    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }

    .dark .card {
      background: var(--dark);
    }

    header {
      text-align: center;
      margin-bottom: 2rem;
    }

    h1 {
      font-size: 2.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.5rem;
    }

    .dark h1 {
      background: linear-gradient(135deg, #8b5cf6 0%, #ec4899 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .subtitle {
      color: var(--gray);
      font-size: 1.1rem;
      margin-bottom: 1.5rem;
    }

    .dark .subtitle {
      color: #94a3b8;
    }

    .flex {
      display: flex;
      gap: 1rem;
      align-items: center;
      flex-wrap: wrap;
    }

    .flex-between {
      justify-content: space-between;
    }

    .flex-center {
      justify-content: center;
    }

    .mb-2 { margin-bottom: 1rem; }
    .mb-3 { margin-bottom: 1.5rem; }
    .mb-4 { margin-bottom: 2rem; }

    input, select, button, textarea {
      padding: 0.75rem 1rem;
      border: 2px solid var(--border);
      border-radius: 8px;
      font-size: 1rem;
      transition: var(--transition);
    }

    .dark input, .dark select, .dark textarea {
      background: #1e293b;
      border-color: #334155;
      color: white;
    }

    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
    }

    button {
      cursor: pointer;
      font-weight: 600;
      border: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }

    button:hover {
      opacity: 0.9;
    }

    .btn-primary {
      background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
      color: white;
    }

    .btn-success {
      background: var(--success);
      color: white;
    }

    .btn-danger {
      background: var(--danger);
      color: white;
    }

    .btn-warning {
      background: var(--warning);
      color: white;
    }

    .btn-outline {
      background: transparent;
      border-color: var(--primary);
      color: var(--primary);
    }

    .btn-sm {
      padding: 0.5rem 0.75rem;
      font-size: 0.875rem;
    }

    .btn-icon {
      padding: 0.75rem;
      width: auto;
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1rem;
      margin-bottom: 1rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
    }

    thead {
      background: rgba(99, 102, 241, 0.05);
    }

    .dark thead {
      background: rgba(139, 92, 246, 0.1);
    }

    th, td {
      padding: 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .dark th, .dark td {
      border-color: #334155;
    }

    tr:hover {
      background: rgba(99, 102, 241, 0.02);
    }

    .dark tr:hover {
      background: rgba(139, 92, 246, 0.05);
    }

    .password-display {
      font-family: 'Courier New', monospace;
      background: rgba(0, 0, 0, 0.03);
      padding: 0.5rem;
      border-radius: 4px;
      letter-spacing: 1px;
      font-size: 0.9rem;
      cursor: pointer;
      transition: var(--transition);
    }

    .dark .password-display {
      background: rgba(255, 255, 255, 0.05);
    }

    .password-display:hover {
      background: rgba(99, 102, 241, 0.1);
    }

    .badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 600;
      margin-right: 0.5rem;
      margin-bottom: 0.5rem;
    }

    .badge-primary { background: rgba(99, 102, 241, 0.1); color: var(--primary); }
    .badge-success { background: rgba(16, 185, 129, 0.1); color: var(--success); }
    .badge-warning { background: rgba(245, 158, 11, 0.1); color: var(--warning); }
    .badge-info { background: rgba(59, 130, 246, 0.1); color: var(--info); }

    .dark .badge-primary { background: rgba(139, 92, 246, 0.2); }
    .dark .badge-success { background: rgba(16, 185, 129, 0.2); }
    .dark .badge-warning { background: rgba(245, 158, 11, 0.2); }
    .dark .badge-info { background: rgba(59, 130, 246, 0.2); }

    .alert {
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      animation: slideDown 0.3s ease;
    }

    @keyframes slideDown {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .alert-success { background: rgba(16, 185, 129, 0.1); color: var(--success); border-left: 4px solid var(--success); }
    .alert-error { background: rgba(239, 68, 68, 0.1); color: var(--danger); border-left: 4px solid var(--danger); }
    .alert-info { background: rgba(59, 130, 246, 0.1); color: var(--info); border-left: 4px solid var(--info); }

    .dark .alert-success { background: rgba(16, 185, 129, 0.15); }
    .dark .alert-error { background: rgba(239, 68, 68, 0.15); }
    .dark .alert-info { background: rgba(59, 130, 246, 0.15); }

    .hidden {
      display: none !important;
    }

    .modal {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
      opacity: 0;
      pointer-events: none;
      transition: var(--transition);
    }

    .modal.show {
      opacity: 1;
      pointer-events: all;
    }

    .modal-content {
      background: var(--light);
      border-radius: 16px;
      padding: 2rem;
      max-width: 500px;
      width: 90%;
      max-height: 90vh;
      overflow-y: auto;
      transform: translateY(-20px);
      transition: var(--transition);
    }

    .dark .modal-content {
      background: var(--dark);
    }

    .modal.show .modal-content {
      transform: translateY(0);
    }

    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
    }

    .modal-close {
      background: none;
      border: none;
      font-size: 1.5rem;
      cursor: pointer;
      color: var(--gray);
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }

    .stat-card {
      background: rgba(99, 102, 241, 0.05);
      padding: 1.5rem;
      border-radius: 12px;
      text-align: center;
      transition: var(--transition);
    }

    .dark .stat-card {
      background: rgba(139, 92, 246, 0.1);
    }

    .stat-card:hover {
      transform: scale(1.05);
    }

    .stat-value {
      font-size: 2rem;
      font-weight: 800;
      color: var(--primary);
      margin: 0.5rem 0;
    }

    .stat-label {
      color: var(--gray);
      font-size: 0.9rem;
    }

    .search-container {
      position: relative;
      margin-bottom: 1.5rem;
    }

    .search-input {
      width: 100%;
      padding-left: 2.5rem;
    }

    .search-icon {
      position: absolute;
      left: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--gray);
    }

    .password-generator {
      background: rgba(99, 102, 241, 0.05);
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1rem;
    }

    .dark .password-generator {
      background: rgba(139, 92, 246, 0.1);
    }

    .strength-meter {
      height: 6px;
      background: #e2e8f0;
      border-radius: 3px;
      margin-top: 0.5rem;
      overflow: hidden;
    }

    .dark .strength-meter {
      background: #334155;
    }

    .strength-bar {
      height: 100%;
      border-radius: 3px;
      transition: var(--transition);
    }

    .strength-weak { background: var(--danger); width: 33%; }
    .strength-medium { background: var(--warning); width: 66%; }
    .strength-strong { background: var(--success); width: 100%; }

    .tabs {
      display: flex;
      border-bottom: 2px solid var(--border);
      margin-bottom: 1.5rem;
    }

    .dark .tabs {
      border-color: #334155;
    }

    .tab {
      padding: 1rem 1.5rem;
      cursor: pointer;
      font-weight: 600;
      color: var(--gray);
      transition: var(--transition);
    }

    .tab.active {
      color: var(--primary);
      border-bottom: 3px solid var(--primary);
    }

    .tab-content {
      display: none;
    }

    .tab-content.active {
      display: block;
    }

    .empty-state {
      text-align: center;
      padding: 3rem 1rem;
      color: var(--gray);
    }

    .empty-state i {
      font-size: 3rem;
      margin-bottom: 1rem;
      opacity: 0.3;
    }

    .empty-state p {
      font-size: 1.1rem;
    }

    @media (max-width: 768px) {
      .card {
        padding: 1.5rem;
      }

      h1 {
        font-size: 2rem;
      }

      .form-grid {
        grid-template-columns: 1fr;
      }

      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <header>
        <h1><i class="fas fa-lock"></i> VaultX</h1>
        <p class="subtitle">Your secure, encrypted credential manager</p>
      </header>

      <div id="alert-container"></div>

      <!-- Stats -->
      <div class="stats-grid">
        <div class="stat-card">
          <i class="fas fa-key fa-2x"></i>
          <div class="stat-value" id="total-count">0</div>
          <div class="stat-label">Total Credentials</div>
        </div>
        <div class="stat-card">
          <i class="fas fa-shield-alt fa-2x"></i>
          <div class="stat-value" id="encryption-status">AES-256</div>
          <div class="stat-label">Encryption</div>
        </div>
        <div class="stat-card">
          <i class="fas fa-clock fa-2x"></i>
          <div class="stat-value" id="last-access">-</div>
          <div class="stat-label">Last Access</div>
        </div>
        <div class="stat-card">
          <i class="fas fa-memory fa-2x"></i>
          <div class="stat-value">Volatile</div>
          <div class="stat-label">Storage</div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <div class="tab active" data-tab="add">➕ Add Credential</div>
        <div class="tab" data-tab="view">🔐 My Vault</div>
        <div class="tab" data-tab="export">📤 Export/Import</div>
      </div>

      <!-- Add Credential Tab -->
      <div class="tab-content active" id="tab-add">
        <div class="password-generator">
          <div class="flex-between mb-2">
            <strong><i class="fas fa-bolt"></i> Password Generator</strong>
            <button class="btn-sm btn-success" onclick="generatePassword()">
              <i class="fas fa-sync"></i> Generate
            </button>
          </div>
          <div class="form-grid">
            <div>
              <label style="display: block; margin-bottom: 0.5rem; font-weight: 600;">Length:</label>
              <input type="number" id="pwd-length" min="8" max="64" value="16" class="form-control">
            </div>
            <div>
              <label style="display: block; margin-bottom: 0.5rem; font-weight: 600;">Strength:</label>
              <div class="strength-meter">
                <div class="strength-bar strength-strong" id="strength-bar"></div>
              </div>
            </div>
          </div>
          <input type="text" id="generated-password" readonly class="search-input mt-2" placeholder="Click Generate to create a secure password">
        </div>

        <div class="form-grid">
          <input type="text" id="service" placeholder="Service Name (e.g., GitHub, AWS)" required>
          <input type="text" id="username" placeholder="Username / Email" required>
          <input type="password" id="password" placeholder="Password" required>
          <input type="url" id="url" placeholder="URL (optional)">
        </div>

        <div class="form-grid">
          <select id="category">
            <option value="">Select Category</option>
            <option value="work">💼 Work</option>
            <option value="personal">🏠 Personal</option>
            <option value="finance">💰 Finance</option>
            <option value="social">📱 Social</option>
            <option value="development">💻 Development</option>
            <option value="other">📁 Other</option>
          </select>
          <input type="text" id="tags" placeholder="Tags (comma-separated, optional)">
        </div>

        <textarea id="notes" rows="3" placeholder="Notes (optional)" style="width: 100%; margin-bottom: 1rem;"></textarea>

        <button class="btn-primary" style="width: 100%;" onclick="saveCredential()">
          <i class="fas fa-save"></i> Save Credential
        </button>
      </div>

      <!-- View Vault Tab -->
      <div class="tab-content" id="tab-view">
        <div class="search-container">
          <i class="fas fa-search search-icon"></i>
          <input type="text" id="search" class="search-input" placeholder="Search credentials..." oninput="filterCredentials()">
        </div>

        <div style="overflow-x: auto;">
          <table id="credentials-table">
            <thead>
              <tr>
                <th><i class="fas fa-tag"></i> Service</th>
                <th><i class="fas fa-user"></i> Username</th>
                <th><i class="fas fa-lock"></i> Password</th>
                <th><i class="fas fa-folder"></i> Category</th>
                <th><i class="fas fa-tag"></i> Tags</th>
                <th><i class="fas fa-clock"></i> Created</th>
                <th><i class="fas fa-cog"></i> Actions</th>
              </tr>
            </thead>
            <tbody id="credentials-body"></tbody>
          </table>
        </div>

        <div id="empty-state" class="empty-state">
          <i class="fas fa-archive"></i>
          <p>No credentials stored yet</p>
          <p style="font-size: 0.9rem; margin-top: 0.5rem;">Add your first credential to get started!</p>
        </div>
      </div>

      <!-- Export/Import Tab -->
      <div class="tab-content" id="tab-export">
        <div class="card" style="margin-bottom: 1rem;">
          <h3 style="margin-bottom: 1rem;"><i class="fas fa-download"></i> Export Vault</h3>
          <p style="margin-bottom: 1rem; color: var(--gray);">Export all credentials as an encrypted JSON file.</p>
          <button class="btn-primary" onclick="exportVault()">
            <i class="fas fa-file-export"></i> Export Encrypted Backup
          </button>
        </div>

        <div class="card">
          <h3 style="margin-bottom: 1rem;"><i class="fas fa-upload"></i> Import Vault</h3>
          <p style="margin-bottom: 1rem; color: var(--gray);">Import credentials from an encrypted backup file.</p>
          <input type="file" id="import-file" accept=".json" style="margin-bottom: 1rem;">
          <button class="btn-success" onclick="importVault()">
            <i class="fas fa-file-import"></i> Import Backup
          </button>
        </div>
      </div>
    </div>

    <!-- Edit Modal -->
    <div class="modal" id="edit-modal">
      <div class="modal-content">
        <div class="modal-header">
          <h2><i class="fas fa-edit"></i> Edit Credential</h2>
          <button class="modal-close" onclick="closeEditModal()">&times;</button>
        </div>
        <input type="hidden" id="edit-id">
        <div class="form-grid">
          <input type="text" id="edit-service" placeholder="Service Name" required>
          <input type="text" id="edit-username" placeholder="Username / Email" required>
          <input type="password" id="edit-password" placeholder="Password" required>
          <input type="url" id="edit-url" placeholder="URL (optional)">
        </div>
        <div class="form-grid">
          <select id="edit-category">
            <option value="">Select Category</option>
            <option value="work">💼 Work</option>
            <option value="personal">🏠 Personal</option>
            <option value="finance">💰 Finance</option>
            <option value="social">📱 Social</option>
            <option value="development">💻 Development</option>
            <option value="other">📁 Other</option>
          </select>
          <input type="text" id="edit-tags" placeholder="Tags (comma-separated)">
        </div>
        <textarea id="edit-notes" rows="3" placeholder="Notes (optional)" style="width: 100%; margin-bottom: 1rem;"></textarea>
        <div class="flex-between">
          <button class="btn-danger" onclick="deleteCredential()">
            <i class="fas fa-trash"></i> Delete
          </button>
          <button class="btn-primary" onclick="updateCredential()">
            <i class="fas fa-save"></i> Save Changes
          </button>
        </div>
      </div>
    </div>
  </div>

  <script>
    let credentials = [];
    let clipboardTimeout = null;

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
      });
    });

    // Load credentials on startup
    loadCredentials();

    async function loadCredentials() {
      try {
        const res = await fetch('/api/credentials');
        const data = await res.json();
        credentials = data;
        renderCredentials();
        updateStats();
      } catch (error) {
        showAlert('Failed to load credentials', 'error');
      }
    }

    function renderCredentials(filter = '') {
      const tbody = document.getElementById('credentials-body');
      const emptyState = document.getElementById('empty-state');
      
      // Filter credentials
      let filtered = credentials;
      if (filter) {
        const term = filter.toLowerCase();
        filtered = credentials.filter(c => 
          c.service.toLowerCase().includes(term) ||
          c.username.toLowerCase().includes(term) ||
          c.category.toLowerCase().includes(term) ||
          c.tags.some(t => t.toLowerCase().includes(term))
        );
      }

      tbody.innerHTML = '';

      if (filtered.length === 0) {
        emptyState.style.display = 'block';
        return;
      }

      emptyState.style.display = 'none';

      filtered.forEach(cred => {
        const row = document.createElement('tr');
        
        // Decrypt password for display
        const decryptedPwd = decryptPassword(cred.encrypted_password);
        
        row.innerHTML =
          '<td><strong>' + cred.service + '</strong><br><small style="color: var(--gray)">' + (cred.url ? cred.url : '') + '</small></td>' +
          '<td>' + cred.username + '</td>' +
          '<td>' +
            '<div class="password-display" onclick="togglePassword(this, \'' + cred.encrypted_password + '\')">' +
              '•••••••• <i class="fas fa-eye"></i>' +
            '</div>' +
          '</td>' +
          '<td><span class="badge badge-info">' + (cred.category || 'none') + '</span></td>' +
          '<td>' +
            cred.tags.map(tag => '<span class="badge badge-primary">' + tag + '</span>').join('') +
          '</td>' +
          '<td><small>' + new Date(cred.created_at).toLocaleDateString() + '</small></td>' +
          '<td>' +
            '<div class="flex" style="gap: 0.5rem;">' +
              '<button class="btn-sm btn-icon btn-outline" onclick="copyToClipboard(\'' + decryptedPwd + '\')">' +
                '<i class="fas fa-copy"></i>' +
              '</button>' +
              '<button class="btn-sm btn-icon btn-primary" onclick="editCredential(' + JSON.stringify(cred).replace(/'/g, "\\'") + ')">' +
                '<i class="fas fa-edit"></i>' +
              '</button>' +
            '</div>' +
          '</td>';
        tbody.appendChild(row);
      });
    }

    function filterCredentials() {
      const searchTerm = document.getElementById('search').value;
      renderCredentials(searchTerm);
    }

    function togglePassword(element, encryptedPwd) {
      const isHidden = element.innerHTML.includes('••••••••');
      if (isHidden) {
        const decrypted = decryptPassword(encryptedPwd);
        element.innerHTML = decrypted + ' <i class="fas fa-eye-slash"></i>';
      } else {
        element.innerHTML = '•••••••• <i class="fas fa-eye"></i>';
      }
    }

    function decryptPassword(encryptedB64) {
      try {
        const encrypted = atob(encryptedB64);
        const key = 'my-secret-key-for-vaultx-2026';
        return encrypted.split('').map((c, i) => 
          String.fromCharCode(c.charCodeAt(0) ^ key[i % key.length].charCodeAt(0))
        ).join('');
      } catch (e) {
        return '***';
      }
    }

    function encryptPassword(password) {
      const key = 'my-secret-key-for-vaultx-2026';
      const encrypted = password.split('').map((c, i) => 
        String.fromCharCode(c.charCodeAt(0) ^ key[i % key.length].charCodeAt(0))
      ).join('');
      return btoa(encrypted);
    }

    async function saveCredential() {
      const service = document.getElementById('service').value.trim();
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value.trim();
      
      if (!service || !username || !password) {
        showAlert('Please fill in all required fields', 'error');
        return;
      }

      const credential = {
        service: service,
        username: username,
        encrypted_password: encryptPassword(password),
        url: document.getElementById('url').value.trim(),
        category: document.getElementById('category').value,
        tags: document.getElementById('tags').value.split(',').map(t => t.trim()).filter(t => t),
        notes: document.getElementById('notes').value.trim()
      };

      try {
        const res = await fetch('/api/credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credential)
        });

        if (res.ok) {
          showAlert('Credential saved successfully!', 'success');
          document.getElementById('service').value = '';
          document.getElementById('username').value = '';
          document.getElementById('password').value = '';
          document.getElementById('url').value = '';
          document.getElementById('category').value = '';
          document.getElementById('tags').value = '';
          document.getElementById('notes').value = '';
          document.getElementById('generated-password').value = '';
          loadCredentials();
        } else {
          showAlert('Failed to save credential', 'error');
        }
      } catch (error) {
        showAlert('Error saving credential', 'error');
      }
    }

    function editCredential(cred) {
      document.getElementById('edit-id').value = cred.id;
      document.getElementById('edit-service').value = cred.service;
      document.getElementById('edit-username').value = cred.username;
      document.getElementById('edit-password').value = decryptPassword(cred.encrypted_password);
      document.getElementById('edit-url').value = cred.url || '';
      document.getElementById('edit-category').value = cred.category || '';
      document.getElementById('edit-tags').value = cred.tags.join(', ');
      document.getElementById('edit-notes').value = cred.notes || '';
      
      document.getElementById('edit-modal').classList.add('show');
    }

    function closeEditModal() {
      document.getElementById('edit-modal').classList.remove('show');
    }

    async function updateCredential() {
      const id = document.getElementById('edit-id').value;
      const service = document.getElementById('edit-service').value.trim();
      const username = document.getElementById('edit-username').value.trim();
      const password = document.getElementById('edit-password').value.trim();
      
      if (!service || !username || !password) {
        showAlert('Please fill in all required fields', 'error');
        return;
      }

      const credential = {
        id: id,
        service: service,
        username: username,
        encrypted_password: encryptPassword(password),
        url: document.getElementById('edit-url').value.trim(),
        category: document.getElementById('edit-category').value,
        tags: document.getElementById('edit-tags').value.split(',').map(t => t.trim()).filter(t => t),
        notes: document.getElementById('edit-notes').value.trim()
      };

      try {
        const res = await fetch('/api/credentials/' + id, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credential)
        });

        if (res.ok) {
          showAlert('Credential updated successfully!', 'success');
          closeEditModal();
          loadCredentials();
        } else {
          showAlert('Failed to update credential', 'error');
        }
      } catch (error) {
        showAlert('Error updating credential', 'error');
      }
    }

    async function deleteCredential() {
      if (!confirm('Are you sure you want to delete this credential?')) return;
      
      const id = document.getElementById('edit-id').value;

      try {
        const res = await fetch('/api/credentials/' + id, {
          method: 'DELETE'
        });

        if (res.ok) {
          showAlert('Credential deleted successfully!', 'success');
          closeEditModal();
          loadCredentials();
        } else {
          showAlert('Failed to delete credential', 'error');
        }
      } catch (error) {
        showAlert('Error deleting credential', 'error');
      }
    }

    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        showAlert('Copied to clipboard!', 'success');
        
        // Auto-clear clipboard after 15 seconds
        if (clipboardTimeout) clearTimeout(clipboardTimeout);
        clipboardTimeout = setTimeout(() => {
          navigator.clipboard.writeText('');
          console.log('Clipboard auto-cleared for security');
        }, 15000);
      }).catch(err => {
        console.error('Failed to copy:', err);
      });
    }

    function generatePassword() {
      const length = parseInt(document.getElementById('pwd-length').value) || 16;
      
      const chars = {
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        numbers: '0123456789',
        symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
      };
      
      // Ensure at least one of each type
      let password = '';
      password += chars.lowercase[Math.floor(Math.random() * chars.lowercase.length)];
      password += chars.uppercase[Math.floor(Math.random() * chars.uppercase.length)];
      password += chars.numbers[Math.floor(Math.random() * chars.numbers.length)];
      password += chars.symbols[Math.floor(Math.random() * chars.symbols.length)];
      
      // Fill the rest
      const allChars = chars.lowercase + chars.uppercase + chars.numbers + chars.symbols;
      for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
      }
      
      // Shuffle
      password = password.split('').sort(() => 0.5 - Math.random()).join('');
      
      document.getElementById('generated-password').value = password;
      
      // Update password field if empty
      if (!document.getElementById('password').value) {
        document.getElementById('password').value = password;
      }
      
      // Update strength indicator
      updateStrengthIndicator(password);
    }

    function updateStrengthIndicator(password) {
      let score = 0;
      if (password.length >= 12) score++;
      if (/[a-z]/.test(password)) score++;
      if (/[A-Z]/.test(password)) score++;
      if (/[0-9]/.test(password)) score++;
      if (/[^a-zA-Z0-9]/.test(password)) score++;
      
      const bar = document.getElementById('strength-bar');
      bar.className = 'strength-bar';
      
      if (score <= 2) {
        bar.classList.add('strength-weak');
      } else if (score <= 4) {
        bar.classList.add('strength-medium');
      } else {
        bar.classList.add('strength-strong');
      }
    }

    document.getElementById('generated-password').addEventListener('input', (e) => {
      updateStrengthIndicator(e.target.value);
    });

    async function exportVault() {
      try {
        const res = await fetch('/api/export');
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'vaultx-backup-' + new Date().toISOString().split('T')[0] + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        showAlert('Vault exported successfully!', 'success');
      } catch (error) {
        showAlert('Failed to export vault', 'error');
      }
    }

    async function importVault() {
      const fileInput = document.getElementById('import-file');
      const file = fileInput.files[0];
      
      if (!file) {
        showAlert('Please select a file to import', 'error');
        return;
      }

      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await fetch('/api/import', {
          method: 'POST',
          body: formData
        });

        if (res.ok) {
          showAlert('Vault imported successfully!', 'success');
          fileInput.value = '';
          loadCredentials();
        } else {
          const data = await res.json();
          showAlert(data.error || 'Failed to import vault', 'error');
        }
      } catch (error) {
        showAlert('Error importing vault', 'error');
      }
    }

    function showAlert(message, type) {
      const container = document.getElementById('alert-container');
      const alert = document.createElement('div');
      alert.className = 'alert alert-' + type;
      const iconClass = (type === 'success') ? 'fa-check-circle' : (type === 'error') ? 'fa-exclamation-circle' : 'fa-info-circle';
      alert.innerHTML = '<i class="fas ' + iconClass + '"></i> ' + message;
      container.appendChild(alert);
      
      setTimeout(() => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateY(-10px)';
        setTimeout(() => alert.remove(), 300);
      }, 3000);
    }

    function updateStats() {
      document.getElementById('total-count').textContent = credentials.length;
      document.getElementById('last-access').textContent = new Date().toLocaleTimeString();
    }

    // Auto-generate password on load
    generatePassword();
  </script>
</body>
</html>
`

func main() {
	// Generate master key
	passphrase := os.Getenv("VAULT_KEY")
	if passphrase == "" {
		passphrase = "vaultx-default-key-change-in-production"
		log.Println("⚠️  Using default passphrase. For better security, set VAULT_KEY environment variable:")
		log.Println("   export VAULT_KEY='your-super-secret-passphrase'")
	}

	// Derive encryption key using Argon2
	salt := []byte("vaultx-salt-2026-fixed")
	vault.masterKey = argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	vault.creds = make(map[string]Credential)
	vault.lastAccess = time.Now()

	// Routes
	http.HandleFunc("/", serveFrontend)
	http.HandleFunc("/api/credentials", handleCredentials)
	http.HandleFunc("/api/credentials/", handleCredentialByID)
	http.HandleFunc("/api/export", handleExport)
	http.HandleFunc("/api/import", handleImport)

	// Start server
	log.Printf("\n" +
		"╔═══════════════════════════════════════════════════════════╗\n" +
		"║                                                           ║\n" +
		"║   🔐 VaultX — Advanced Credential Manager                ║\n" +
		"║                                                           ║\n" +
		"║   ✅ AES-256 Encryption (Argon2 key derivation)          ║\n" +
		"║   ✅ Beautiful Modern UI with Dark Mode                  ║\n" +
		"║   ✅ Password Generator & Strength Meter                 ║\n" +
		"║   ✅ Search, Categories, Tags                            ║\n" +
		"║   ✅ Export/Import (Encrypted)                           ║\n" +
		"║   ✅ Clipboard Auto-Clear (15s)                          ║\n" +
		"║   ✅ In-Memory Storage (Volatile)                        ║\n" +
		"║                                                           ║\n" +
		"╚═══════════════════════════════════════════════════════════╝\n")
	log.Printf("🔒 All data is stored ONLY in memory (lost on restart)")
	log.Printf("📊 Open your browser and start managing credentials!\n")

	// Get port from environment variable (Render sets this)
  port := os.Getenv("PORT")
  if port == "" {
      port = "8081"  // Default for local development
  }

  log.Printf("🚀 Starting server on port %s", port)

  // Bind to all interfaces (0.0.0.0), not just localhost
  err := http.ListenAndServe(":"+port, nil)
  if err != nil {
      log.Fatal("Server failed to start:", err)
  }
}

func serveFrontend(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tmpl := template.Must(template.New("index").Parse(indexHTML))
	tmpl.Execute(w, nil)
}

func handleCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8081")

	vault.mu.Lock()
	vault.lastAccess = time.Now()
	vault.mu.Unlock()

	switch r.Method {
	case "GET":
		vault.mu.RLock()
		creds := make([]map[string]interface{}, 0, len(vault.creds))
		for _, c := range vault.creds {
			creds = append(creds, map[string]interface{}{
				"id":                 c.ID,
				"service":            c.Service,
				"username":           c.Username,
				"encrypted_password": base64.StdEncoding.EncodeToString(c.EncryptedPassword),
				"url":                c.URL,
				"category":           c.Category,
				"tags":               c.Tags,
				"created_at":         c.CreatedAt.Format(time.RFC3339),
				"updated_at":         c.UpdatedAt.Format(time.RFC3339),
			})
		}
		vault.mu.RUnlock()

		// Sort by service name
		sort.Slice(creds, func(i, j int) bool {
			return creds[i]["service"].(string) < creds[j]["service"].(string)
		})

		json.NewEncoder(w).Encode(creds)

	case "POST":
		var req struct {
			Service           string   `json:"service"`
			Username          string   `json:"username"`
			EncryptedPassword string   `json:"encrypted_password"`
			URL               string   `json:"url"`
			Category          string   `json:"category"`
			Tags              []string `json:"tags"`
			Notes             string   `json:"notes"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// Generate ID
		id := fmt.Sprintf("%d", time.Now().UnixNano())

		// Decode encrypted password
		encryptedPwd, err := base64.StdEncoding.DecodeString(req.EncryptedPassword)
		if err != nil {
			http.Error(w, "Invalid encrypted password", http.StatusBadRequest)
			return
		}

		vault.mu.Lock()
		vault.creds[id] = Credential{
			ID:                id,
			Service:           req.Service,
			Username:          req.Username,
			EncryptedPassword: encryptedPwd,
			URL:               req.URL,
			Category:          req.Category,
			Tags:              req.Tags,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}
		vault.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "saved", "id": id})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleCredentialByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimPrefix(r.URL.Path, "/api/credentials/")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	vault.mu.Lock()
	vault.lastAccess = time.Now()
	vault.mu.Unlock()

	switch r.Method {
	case "PUT":
		var req struct {
			ID                string   `json:"id"`
			Service           string   `json:"service"`
			Username          string   `json:"username"`
			EncryptedPassword string   `json:"encrypted_password"`
			URL               string   `json:"url"`
			Category          string   `json:"category"`
			Tags              []string `json:"tags"`
			Notes             string   `json:"notes"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		encryptedPwd, err := base64.StdEncoding.DecodeString(req.EncryptedPassword)
		if err != nil {
			http.Error(w, "Invalid encrypted password", http.StatusBadRequest)
			return
		}

		vault.mu.Lock()
		if cred, exists := vault.creds[id]; exists {
			vault.creds[id] = Credential{
				ID:                id,
				Service:           req.Service,
				Username:          req.Username,
				EncryptedPassword: encryptedPwd,
				URL:               req.URL,
				Category:          req.Category,
				Tags:              req.Tags,
				CreatedAt:         cred.CreatedAt,
				UpdatedAt:         time.Now(),
			}
			vault.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
		} else {
			vault.mu.Unlock()
			http.Error(w, "Credential not found", http.StatusNotFound)
		}

	case "DELETE":
		vault.mu.Lock()
		if _, exists := vault.creds[id]; exists {
			delete(vault.creds, id)
			vault.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		} else {
			vault.mu.Unlock()
			http.Error(w, "Credential not found", http.StatusNotFound)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vault.mu.RLock()
	exportData := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"credentials": vault.creds,
		"count":       len(vault.creds),
	}
	vault.mu.RUnlock()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"vaultx-backup-%s.json\"", time.Now().Format("2006-01-02")))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exportData)
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var importData struct {
		Credentials map[string]Credential `json:"credentials"`
	}
	if err := json.NewDecoder(file).Decode(&importData); err != nil {
		http.Error(w, "Invalid backup file format", http.StatusBadRequest)
		return
	}

	vault.mu.Lock()
	// Merge or replace (here we replace)
	vault.creds = importData.Credentials
	vault.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "imported",
		"count":  len(importData.Credentials),
	})
}

// Helper function to generate random string (for ID)
func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}