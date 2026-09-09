# Lynx frontend

The React frontend for the Lynx investigation console. It talks to the
FastAPI backend, which reads Elasticsearch directly.

## What is here

- Case queue with risk scores and severity
- Investigation view with the behavior timeline and the cross-layer tab
- Process-tree explorer (D3)
- Hunt workbench with the query templates
- Coverage map and the analyst actions log

## Stack

React 19, TypeScript, Vite, Ant Design, TanStack Query, D3.

## Running it

The backend must be up and reachable on port 8000.

```bash
npm install
npm run dev
```

The dev server runs on port 5173.

## Building

```bash
npm run build
```

This runs the TypeScript check and produces the production bundle in `dist/`.
