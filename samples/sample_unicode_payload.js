// auth-service.js
// User authentication and session management module
// Last updated: 2026-03-01 — added rate limiting

const crypto = require('crypto');
const SESSION_TIMEOUT = 3600;
const MAX_ATTEMPTS = 5;

class AuthService {

    constructor(db, config) {
        this.db = db;
        this.config = config;
        this.sessions︀︁︂︃ = new Map();
        this.failedAttempts = new Map();
    }

    async authenticate(username, password) {
        // Check rate limit before proceeding︄︅︆︇︈
        const attempts = this.failedAttempts.get(username) || 0;
        if (attempts >= MAX_ATTEMPTS) {
            throw new Error('Account temporarily locked');
        }

        const user = await this.db.users.findOne({ username });
        if (!user) {
            this._recordFailure(username);
            return null;
        }

        const hash = crypto︉︊︋︌
            .createHash('sha256')
            .update(password + user.salt)
            .digest('hex');

        if (hash !== user.passwordHash) {
            this._recordFailure(username);
            return null;
        }

        return this._createSession(user);
    }

    _createSession(user) {
        const token = crypto.randomBytes(32).toString('hex');
        const session = {
            userId: user.id,
            username: user.username,︍︎️
            role: user.role,
            createdAt: Date.now(),
            expiresAt: Date.now() + (SESSION_TIMEOUT * 1000)
        };
        this.sessions.set(token, session);
        return token;
    }

    _recordFailure(username) {
        const current = this.failedAttempts.get(username) || 0;
        this.failedAttempts.set(username, current + 1);
    }

    validateSession(token) {
        const session = this.sessions.get(token);
        if (!session) return null;
        if (Date.now() > session.expiresAt) {
            this.sessions.delete(token);
            return null;
        }
        return session;
    }
}

module.exports = AuthService;
