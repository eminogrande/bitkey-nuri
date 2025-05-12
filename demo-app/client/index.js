import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

const API_URL = window.location.hostname === 'localhost' 
  ? 'http://localhost:3000' 
  : 'https://fido2-demo-server.fly.dev';
const REGISTER_START_URL = `${API_URL}/api/register/start`;
const REGISTER_COMPLETE_URL = `${API_URL}/api/register/complete`;
const AUTH_START_URL = `${API_URL}/api/authenticate/start`;
const AUTH_COMPLETE_URL = `${API_URL}/api/authenticate/complete`;
const USERS_URL = `${API_URL}/api/users`;

const registerForm = document.getElementById('register-form');
const registerUsername = document.getElementById('register-username');
const authForm = document.getElementById('auth-form');
const authUsername = document.getElementById('auth-username');
const statusMessage = document.getElementById('status-message');
const refreshUsersBtn = document.getElementById('refresh-users');
const userList = document.getElementById('user-list');

function showStatus(message, isError = false) {
    statusMessage.textContent = message;
    statusMessage.classList.remove('hidden', 'alert-success', 'alert-danger');
    statusMessage.classList.add(isError ? 'alert-danger' : 'alert-success');
}

function hideStatus() {
    statusMessage.classList.add('hidden');
}

async function fetchWithErrorHandling(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'An error occurred');
        }
        
        return await response.json();
    } catch (error) {
        showStatus(error.message, true);
        throw error;
    }
}

registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    hideStatus();
    
    const username = registerUsername.value.trim();
    if (!username) {
        showStatus('Username is required', true);
        return;
    }
    
    try {
        const registrationOptions = await fetchWithErrorHandling(REGISTER_START_URL, {
            method: 'POST',
            body: JSON.stringify({ username })
        });
        
        const attestationResponse = await startRegistration(registrationOptions);
        
        const verificationResult = await fetchWithErrorHandling(REGISTER_COMPLETE_URL, {
            method: 'POST',
            body: JSON.stringify({
                username,
                attestationResponse
            })
        });
        
        if (verificationResult.verified) {
            showStatus(`Registration successful for ${username}!`);
            registerForm.reset();
            loadUsers();
        } else {
            showStatus('Registration failed', true);
        }
    } catch (error) {
        console.error('Registration error:', error);
        showStatus(`Registration failed: ${error.message}`, true);
    }
});

authForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    hideStatus();
    
    const username = authUsername.value.trim();
    if (!username) {
        showStatus('Username is required', true);
        return;
    }
    
    try {
        const authenticationOptions = await fetchWithErrorHandling(AUTH_START_URL, {
            method: 'POST',
            body: JSON.stringify({ username })
        });
        
        const assertionResponse = await startAuthentication(authenticationOptions);
        
        const verificationResult = await fetchWithErrorHandling(AUTH_COMPLETE_URL, {
            method: 'POST',
            body: JSON.stringify({
                username,
                assertionResponse
            })
        });
        
        if (verificationResult.verified) {
            showStatus(`Authentication successful for ${username}!`);
            authForm.reset();
        } else {
            showStatus('Authentication failed', true);
        }
    } catch (error) {
        console.error('Authentication error:', error);
        showStatus(`Authentication failed: ${error.message}`, true);
    }
});

async function loadUsers() {
    try {
        const users = await fetchWithErrorHandling(USERS_URL);
        
        if (users.length === 0) {
            userList.innerHTML = '<p>No users registered yet.</p>';
            return;
        }
        
        const userTable = document.createElement('table');
        userTable.className = 'table table-striped';
        
        const tableHead = document.createElement('thead');
        tableHead.innerHTML = `
            <tr>
                <th>Username</th>
                <th>User ID</th>
                <th>Authenticators</th>
            </tr>
        `;
        
        const tableBody = document.createElement('tbody');
        users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${user.username}</td>
                <td>${user.id}</td>
                <td>${user.authenticators}</td>
            `;
            tableBody.appendChild(row);
        });
        
        userTable.appendChild(tableHead);
        userTable.appendChild(tableBody);
        
        userList.innerHTML = '';
        userList.appendChild(userTable);
    } catch (error) {
        console.error('Error loading users:', error);
        userList.innerHTML = '<p class="text-danger">Error loading users</p>';
    }
}

refreshUsersBtn.addEventListener('click', loadUsers);

loadUsers();
