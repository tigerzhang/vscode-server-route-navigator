# Server Route Navigator - VS Code Extension

![Server Route Navigator](./vscode-server-route.png)

This extension provides a CodeLens and command to navigate from a client API route string (e.g., `/api/purchase/verify`) to the server-side handler by searching server code for the route string.

Features:
- Show a CodeLens action "Go to server handler" above lines containing `/api/...`.
- Click CodeLens or run the command to search for matching server-side handlers and open them.

Usage:
- Open a Dart file that refers to an API route as a string literal. A CodeLens appears above it.
- Click "Go to server handler" to jump to the matching handler in `AI-Earphone-server` or choose from multiple matches.

Notes:
- This extension searches for the string across server files (Rust, JS, TS, Python, Go) in `AI-Earphone-server` by default.
- The search is literal string matching; it works best if the route path is a literal string in the client file.