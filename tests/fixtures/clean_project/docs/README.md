# Setup

Export your credentials before running the app:

```sh
export GITHUB_TOKEN=ghp_your_token_here
export STRIPE_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx
export DATABASE_URL=postgres://user:password@localhost:5432/app
```

Never commit real values. Use `${SECRET_NAME}` references in config files.
