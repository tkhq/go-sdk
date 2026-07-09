# Example: `whoami`

A sample script that demonstrates how to retrieve information about the authenticated API key and its associated organization.

### 1/ Setup

Follow the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) to get your API key and organization ID.

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/whoami/.env.example examples/whoami/.env
```

### 2/ Running

```bash
set -a && source examples/whoami/.env && set +a && go run ./examples/whoami
```

Prints the user ID and organization ID associated with the authenticated API key on success.

