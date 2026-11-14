-- Demo accounts for local development. There is no sign-up page yet, so
-- accounts are created here. Never load this into a shared database.
--   alice@example.com / password123  (user)
--   mod@example.com   / password123  (moderator)

INSERT INTO users (email, password_hash, role)
VALUES
    ('alice@example.com', crypt('password123', gen_salt('bf')), 'user'),
    ('mod@example.com', crypt('password123', gen_salt('bf')), 'moderator')
ON CONFLICT (lower(email)) DO NOTHING;
