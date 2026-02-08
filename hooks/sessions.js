const crypto = require("crypto");

module.exports = {
  runContextHook({ context, db }) {
    context.newSession = (userId) => {
      const token = "ft2$" + crypto.randomBytes(48).toString('hex');
      
      db.run(`
        INSERT INTO sessions (id, user_id, token) VALUES ($->new_id(), ?, ?)
      `, userId, token);

      return token;
    };

    context.isSessionValid = (token) => {
      if (!token) {
        return false;
      }

      const session = db.get(`
        SELECT 1 FROM sessions WHERE token = ? LIMIT 1
      `, token);

      return session != undefined;
    };

    context.isLoggedIn = () => {
      return context.thisUser != null;
    };
  },

  refreshUser({ context, db, User }) {
    const authHeader = context.req?.headers?.["authorization"];
    context.thisUser = null;

    if (authHeader) {
      const session = db.get(`
        SELECT user_id FROM sessions WHERE token = ? LIMIT 1
      `, authHeader);

      if (session != undefined) {
        const user = db.get(`
          SELECT ${User.ALL} FROM users WHERE id = ? LIMIT 1
        `, session.user_id);

        if (user != undefined) {
          context.thisUser = user;
        }
      }
    }
  },

  async runFunctionHook(name, body, { context, isLoggedIn, FunctionError }, func) {
    if (func.requireAuth && !isLoggedIn()) {
      throw new FunctionError("authRequired");
    }

    this.refreshUser(context);
  },

  async runViewHook(route, { context, isLoggedIn, FunctionError }, view) {
    if (view.backend?.requireAuth && !isLoggedIn()) {
      throw new FunctionError("authRequired");
    }

    this.refreshUser(context);
  },

  async runRefreshHook({ context }) {
    this.refreshUser(context);
  }
};