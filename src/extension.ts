import * as vscode from 'vscode';

// Output channel for the extension (visible in VS Code 'Output' panel)
const OUTPUT_CHANNEL = vscode.window.createOutputChannel('Server Route Navigator');

// Debug flag when set to '1' as env var SRN_DEBUG or DEBUG includes package name
const DEBUG = !!(
  process.env.SRN_DEBUG === '1' || (process.env.DEBUG && process.env.DEBUG.includes('server-route-navigator'))
);

function debugLog(...args: any[]) {
  if (DEBUG) {
    console.log('[serverRouteNavigator]', ...args);
    outputLog(...args);
  }
}

function outputLog(...args: any[]) {
  const msg = args.map((a) => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ');
  OUTPUT_CHANNEL.appendLine(`${new Date().toISOString()} ${msg}`);
}

// Languages and glob to search in server folder
const SERVER_GLOB = 'AI-Earphone-server/**/*.{rs,js,ts,py,go}';

export function activate(context: vscode.ExtensionContext) {
  outputLog('Activating serverRouteNavigator extension');
  console.log('Extension "serverRouteNavigator" is now active!');
  debugLog('Debug enabled');
  const provider = new ServerRouteCodeLensProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider({ language: 'dart' }, provider)
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      'serverRouteNavigator.goToServerHandler',
      async (rangeOrPath?: any) => {
        debugLog('Command invoked with argument:', rangeOrPath);
        // If a CodeLens invoked with path string, it passes argument; otherwise extract from editor
        const editor = vscode.window.activeTextEditor;
        if (!editor && typeof rangeOrPath !== 'string') {
          vscode.window.showInformationMessage('No active editor');
          return;
        }

        let pathToSearch: string | undefined;

        if (typeof rangeOrPath === 'string') {
          pathToSearch = rangeOrPath;
        } else if (rangeOrPath && rangeOrPath.path) {
          pathToSearch = rangeOrPath.path;
        } else if (editor) {
          const selection = editor.selection;
          pathToSearch = extractPathLiteralAt(editor.document, selection.start);
          if (!pathToSearch) {
            // Try whole line
            pathToSearch = extractPathLiteralFromLine(editor.document, selection.start.line);
          }
        }

        if (!pathToSearch) {
          vscode.window.showInformationMessage('No API path found at cursor');
          return;
        }

        const normalizedPathForLog = normalizeSearchPath(pathToSearch);
        const matches = await findServerHandler(pathToSearch);
        if (matches.length === 0) {
          vscode.window.showInformationMessage(`No server handler found for ${pathToSearch}`);
          outputLog('No server handler found', { path: normalizedPathForLog, original: pathToSearch });
          return;
        }

        if (matches.length === 1) {
          const m = matches[0];
          // Show a contextual popup with the match snippet and allow Open or Preview
          const openAction = 'Open';
          const previewAction = 'Preview';
          const choice = await vscode.window.showInformationMessage(
            `Found 1 match: ${m.uri.fsPath}:${m.line + 1}\n${m.snippet}`,
            { modal: false },
            openAction,
            previewAction
          );
          if (choice === openAction) {
            const doc = await vscode.workspace.openTextDocument(m.uri);
            const ed = await vscode.window.showTextDocument(doc);
            ed.revealRange(m.range, vscode.TextEditorRevealType.InCenter);
            ed.selection = new vscode.Selection(m.range.start, m.range.end);
          } else if (choice === previewAction) {
            const doc = await vscode.workspace.openTextDocument(m.uri);
            const ed = await vscode.window.showTextDocument(doc, { preview: true, preserveFocus: true });
            ed.revealRange(m.range, vscode.TextEditorRevealType.InCenter);
            ed.selection = new vscode.Selection(m.range.start, m.range.end);
          }
          return;
        }

        // Present contextual QuickPick with preview on selection
        const quickPick = vscode.window.createQuickPick<any>();
        quickPick.title = `Multiple server matches for ${pathToSearch}`;
        quickPick.matchOnDescription = true;
        quickPick.matchOnDetail = true;
        quickPick.items = matches.map((m) => ({
          label: `${m.uri.fsPath}:${m.line + 1}`,
          description: `${m.source}${m.meta?.matchType ? ' (' + m.meta.matchType + ')' : ''}`,
          detail: `${m.meta?.route ?? ''} — ${m.snippet}`,
          match: m,
        }));

        quickPick.onDidChangeSelection(async (selection) => {
          if (!selection || selection.length === 0) return;
          const sel = selection[0];
          const m = sel.match;
          try {
            const doc = await vscode.workspace.openTextDocument(m.uri);
            await vscode.window.showTextDocument(doc, { preview: true, preserveFocus: true });
            const ed = vscode.window.activeTextEditor;
            if (ed) {
              ed.revealRange(m.range, vscode.TextEditorRevealType.InCenter);
            }
          } catch (e) {
            debugLog('Error previewing document', e);
          }
        });

        quickPick.onDidAccept(async () => {
          const selection = quickPick.selectedItems[0];
          if (selection) {
            const m = selection.match;
            outputLog('User selected match', { file: m.uri.fsPath, line: m.line + 1, source: m.source, route: m.meta?.route });
            const doc = await vscode.workspace.openTextDocument(m.uri);
            const ed = await vscode.window.showTextDocument(doc);
            ed.revealRange(m.range, vscode.TextEditorRevealType.InCenter);
            ed.selection = new vscode.Selection(m.range.start, m.range.end);
          }
          quickPick.hide();
        });

        quickPick.onDidHide(() => quickPick.dispose());
        quickPick.show();
      }
    )
  );

  // Refresh codelenses when text documents change
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      provider['onDidChangeCodeLensesEmitter'].fire();
    })
  );
}

export function deactivate() {}

class ServerRouteCodeLensProvider implements vscode.CodeLensProvider {
  private onDidChangeCodeLensesEmitter = new vscode.EventEmitter<void>();
  public readonly onDidChangeCodeLenses = this.onDidChangeCodeLensesEmitter.event;

  public async provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken) {
    const codeLenses: vscode.CodeLens[] = [];
    const text = document.getText();
    const regex = new RegExp("(\\\"|\\')(/api/[^\\\"']+)(\\\"|\\')", 'g');
    let match: RegExpExecArray | null;
      while ((match = regex.exec(text)) && !token.isCancellationRequested) {
        const path = match[2];
        const matchIndex = match.index;
        // match[0] = '"/api/..."' or similar; match[1] is the quote char. compute inner start/end
        const innerStartIndex = matchIndex + (match[1] ? match[1].length : 1);
        const innerEndIndex = innerStartIndex + path.length;
        const startPos = document.positionAt(innerStartIndex);
        const endPos = document.positionAt(innerEndIndex);
      const range = new vscode.Range(startPos, endPos);

      // Add CodeLens that calls command with path argument
      const cmd: vscode.Command = {
        title: 'Server Route Navigator: Go To Server Handler',
        command: 'serverRouteNavigator.goToServerHandler',
        arguments: [{ path }],
      };
      codeLenses.push(new vscode.CodeLens(range, cmd));
    }
    debugLog('provideCodeLenses', document.uri.fsPath, 'found', codeLenses.length, 'codelenses');
    return codeLenses;
  }

  public resolveCodeLens(codeLens: vscode.CodeLens, token: vscode.CancellationToken) {
    return codeLens;
  }
}

function extractPathLiteralAt(document: vscode.TextDocument, position: vscode.Position): string | undefined {
  const line = document.lineAt(position.line).text;
  // Find quotes on either side
  const regex = /(\"|\')(\/api\/[^\"']+)(\"|\')/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(line))) {
    const start = match.index;
    const end = start + match[0].length;
    if (position.character >= start && position.character <= end) {
      debugLog('extractPathLiteralAt', document.uri.fsPath, 'cursor', position.line, position.character, 'found', match[2]);
      return match[2];
    }
  }
  return undefined;
}

function extractPathLiteralFromLine(document: vscode.TextDocument, lineNumber: number) {
  const line = document.lineAt(lineNumber).text;
  const regex = /(\"|\')(\/api\/[^\"']+)(\"|\')/g;
  const match = regex.exec(line);
  if (match) debugLog('extractPathLiteralFromLine', document.uri.fsPath, 'line', lineNumber, 'found', match[2]);
  return match ? match[2] : undefined;
}

async function findServerHandler(pathToSearch: string) {
  // debugLog('Searching for server handler for path:', pathToSearch, 'using glob:', SERVER_GLOB);
  const normalizedPath = normalizeSearchPath(pathToSearch);
  // debugLog('Normalized search path:', normalizedPath);
  const lastSegment = getLastPathSegment(normalizedPath);
  // debugLog('Derived last segment:', lastSegment);
  const results: {
    uri: vscode.Uri;
    line: number;
    range: vscode.Range;
    snippet: string;
    source?: string;
    meta?: any;
  }[] = [];
  // Search common server project folders (AI-Earphone-server) and the repo root
  const files = await vscode.workspace.findFiles(SERVER_GLOB, '**/node_modules/**', 1000);
  debugLog('findServerHandler files found:', files.length);

  for (const file of files) {
    try {
      // debugLog('Processing file:', file.fsPath);
      const doc = await vscode.workspace.openTextDocument(file);
      const text = doc.getText();
      const lines = text.split(/\r?\n/);
      // If Rust file, also look for Actix-web route annotations and resources
      if (file.fsPath.endsWith('.rs')) {
        // log filename and path being searched
        // debugLog(`Searching in Rust file: ${file.fsPath} for path: ${pathToSearch}`);
        const actixMatches = extractActixRoutes(text);
        // debugLog('Actix matches for file', file.fsPath, actixMatches.length);
        for (const m of actixMatches) {
          if (isLastSegmentPlaceholder(m.route)) {
            debugLog('Skipping route because last segment is a placeholder', m.route, 'at', file.fsPath + ':' + (m.line + 1));
            outputLog('Skipping placeholder-last-segment route match', { file: file.fsPath, route: m.route, line: m.line + 1 });
            continue;
          }
                if (isGenericRoute(m.route)) {
                  debugLog('Skipping generic route (placeholder-only)', m.route, 'at', file.fsPath + ':' + (m.line + 1));
                  continue;
                }
          const doesMatchFull = actixPatternMatches(m.route, normalizedPath);
          let doesMatchLastSeg = false;
          if (!doesMatchFull && lastSegment && lastSegment !== '/') {
            doesMatchLastSeg = m.route.endsWith(lastSegment) || actixPatternMatches(m.route, lastSegment);
          }
          debugLog('actix route', m.route, 'line', m.line, 'matchesFull', doesMatchFull, 'matchesLastSeg', doesMatchLastSeg);
          if (doesMatchFull || doesMatchLastSeg) {
            const start = new vscode.Position(m.line, Math.max(0, m.col - 2));
            const end = new vscode.Position(m.line, m.col + m.route.length + 2);
            const snippet = lines[m.line].trim().slice(0, 160);
            results.push({ uri: file, line: m.line, range: new vscode.Range(start, end), snippet, source: 'actix', meta: { route: m.route, matchType: doesMatchFull ? 'full' : 'lastSegment' } });
            outputLog('Found actix match', { file: file.fsPath, line: m.line + 1, route: m.route, matchType: doesMatchFull ? 'full' : 'lastSegment' });
          }
        }
      }

      // Fallback text search as before
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(normalizedPath)) {
          const idxMatch = lines[i].indexOf(normalizedPath);
          if (isInComment(lines[i], idxMatch)) {
            debugLog('Skipping normalizedPath match inside comment', file.fsPath, 'line', i, 'idx', idxMatch);
            outputLog('Skipping normalizedPath match inside comment', { file: file.fsPath, line: i + 1, idx: idxMatch, path: normalizedPath });
            continue;
          }
          if (isWithinAbsoluteUrl(lines[i], idxMatch)) {
            debugLog('Skipping normalizedPath match inside absolute URL', file.fsPath, 'line', i, 'idx', idxMatch);
            outputLog('Skipping normalizedPath match inside absolute URL', { file: file.fsPath, line: i + 1, idx: idxMatch, path: normalizedPath });
            continue;
          }
          debugLog('text match found', file.fsPath, 'line', i);
          const idx = idxMatch;
          const start = new vscode.Position(i, Math.max(0, idx - 2));
          const end = new vscode.Position(i, idx + pathToSearch.length + 2);
          const snippet = lines[i].trim().slice(0, 160);
          results.push({ uri: file, line: i, range: new vscode.Range(start, end), snippet, source: 'text' });
          outputLog('Found text match', { file: file.fsPath, line: i + 1, snippet });
        } else if (lastSegment && lastSegment !== '/' && lastSegment.length > 0) {
          const segWithSlash = lastSegment; // lastSegment now includes leading '/'
          let idxSeg = lines[i].indexOf(segWithSlash);
          if (idxSeg !== -1 && isInComment(lines[i], idxSeg)) {
            debugLog('Skipping segWithSlash match in comment', file.fsPath, 'line', i, 'seg', segWithSlash);
            outputLog('Skipping segWithSlash match in comment', { file: file.fsPath, line: i + 1, seg: segWithSlash });
            idxSeg = -1; // ensure we don't treat as a segment match
          }
          if (idxSeg !== -1 && isWithinAbsoluteUrl(lines[i], idxSeg)) {
            debugLog('Skipping segWithSlash match inside absolute URL', file.fsPath, 'line', i, 'seg', segWithSlash);
            outputLog('Skipping segWithSlash match inside absolute URL', { file: file.fsPath, line: i + 1, seg: segWithSlash });
            idxSeg = -1;
          }
          const segNoSlash = lastSegment.replace(/\//, '');
          let idxSeg2 = -1;
          let searchPos = 0;
          while (true) {
            const found = lines[i].indexOf(segNoSlash, searchPos);
            if (found === -1) break;
            if (isPotentialPathMatch(lines[i], found, segNoSlash) && !isInComment(lines[i], found) && isInsideString(lines[i], found) && !isWithinAbsoluteUrl(lines[i], found)) {
              idxSeg2 = found;
              break;
            }
            else {
              debugLog('Found candidate seg occurence in comment or identifier, skipping', lines[i].trim().slice(0, 160), 'pos', found);
              outputLog('Skipping segNoSlash occurence', { file: file.fsPath, line: i + 1, pos: found, context: lines[i].trim().slice(0, 160) });
            }
            searchPos = found + 1;
            if (searchPos > 300) break; // avoid scanning arbitrarily long lines
          }
          if (idxSeg !== -1 || idxSeg2 !== -1) {
            debugLog('last-segment text match found', file.fsPath, 'line', i, 'segment', lastSegment);
            const idx2 = idxSeg !== -1 ? idxSeg : idxSeg2;
            const start2 = new vscode.Position(i, Math.max(0, idx2 - 2));
            const end2 = new vscode.Position(i, idx2 + lastSegment.length + 2);
            const snippet2 = lines[i].trim().slice(0, 160);
            results.push({ uri: file, line: i, range: new vscode.Range(start2, end2), snippet: snippet2, source: 'lastSegment' });
            outputLog('Found last-segment match', { file: file.fsPath, line: i + 1, segment: lastSegment, snippet: snippet2 });
          }
        }
      }
    } catch (e) {
      // ignore
    }
  }

  debugLog('Total matches found (raw):', results.length);
  // Deduplicate by file path and line
  const uniqueMap = new Map<string, { uri: vscode.Uri; line: number; range: vscode.Range; snippet: string; source?: string; meta?: any }>();
  for (const r of results) {
    const key = `${r.uri.fsPath}:${r.line}`;
    if (!uniqueMap.has(key)) uniqueMap.set(key, r);
  }
  const uniqueResults = Array.from(uniqueMap.values());
  debugLog('Unique matches after dedupe:', uniqueResults.length);
  outputLog('Matches summary:', uniqueResults.map((r) => ({ path: r.meta?.route ?? '<text-match>', file: r.uri.fsPath, line: r.line + 1, source: r.source, matchType: r.meta?.matchType })));
  const sorted = uniqueResults.sort((a, b) => a.line - b.line);
  // Also output the final sorted list
  outputLog('Sorted matches:', sorted.map((r) => ({ file: r.uri.fsPath, line: r.line + 1, source: r.source, route: r.meta?.route })));
  return sorted;
}

// Extract possible Actix route patterns from Rust source
function extractActixRoutes(text: string): { route: string; line: number; col: number }[] {
  const result: { route: string; line: number; col: number }[] = [];
  const lines = text.split(/\r?\n/);

  const attrRegex = /#\s*\[(?:get|post|put|delete|patch|head|options|route)\s*\(\s*"([^"]+)"/i;
  const resourceRegex = /(?:web::)?resource\s*\(\s*"([^"]+)"\s*\)/g;
  const scopeRegex = /web::scope\s*\(\s*"([^"]+)"\s*\)/g;
  const routeCallRegex = /\.route\s*\(\s*["']([^"']+)["']\s*,/g;

  const scopes: { path: string; line: number }[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // attribute macros like #[get("/api/foo/{id}")]
    const attrMatch = attrRegex.exec(line);
    if (attrMatch) {
      debugLog('extractActixRoutes found attr macro', attrMatch[1], 'on line', i);
      result.push({ route: attrMatch[1], line: i, col: line.indexOf(attrMatch[1]) });
    }

    // scoping e.g. web::scope("/api")
    let scopeMatch: RegExpExecArray | null;
    while ((scopeMatch = scopeRegex.exec(line)) !== null) {
      debugLog('extractActixRoutes found scope', scopeMatch[1], 'on line', i);
      scopes.push({ path: scopeMatch[1].replace(/"/g, ''), line: i });
    }

    // explicit web::resource("/path") matches
    let resourceMatch: RegExpExecArray | null;
    while ((resourceMatch = resourceRegex.exec(line)) !== null) {
      debugLog('extractActixRoutes found resource', resourceMatch[1], 'on line', i);
      result.push({ route: resourceMatch[1], line: i, col: line.indexOf(resourceMatch[1]) });
    }

    // .route("/path", web::post().to(handler)) style
    let routeCallMatch: RegExpExecArray | null;
    while ((routeCallMatch = routeCallRegex.exec(line)) !== null) {
      debugLog('extractActixRoutes found route call', routeCallMatch[1], 'on line', i);
      result.push({ route: routeCallMatch[1], line: i, col: line.indexOf(routeCallMatch[1]) });
    }
  }

  // Combine scopes with resource routes to produce full paths
  const fullResults: { route: string; line: number; col: number }[] = [];
  // Add direct results first
  for (const r of result) fullResults.push(r);

  // For each scope, try to combine with nearby resource definitions
  for (const s of scopes) {
    for (const r of result) {
      // Only combine when resource is in the same file and resource's line is after scope (best-effort)
      if (r.line > s.line && r.route.startsWith('/')) {
        const combined = (s.path.endsWith('/') ? s.path.slice(0, -1) : s.path) + r.route;
        debugLog('extractActixRoutes combining scope', s.path, 'with route', r.route, '->', combined);
        fullResults.push({ route: combined, line: r.line, col: r.col });
      }
    }
  }

  return fullResults;
}

// Match Actix route pattern to a path. Convert {var} to wildcard and compare.
function actixPatternMatches(routePattern: string, path: string): boolean {
  // Normalize: remove trailing slash
  const normalize = (s: string) => s.replace(/\/$/, '');
  const rp = normalize(routePattern);
  const p = normalize(path);
  // Escape regex except for placeholders {var}
  let reStr = rp.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&');
  // Replace escaped placeholders like \{id\} back to unescaped and then to wildcard
  reStr = reStr.replace(/\\\{[^}]+\\\}/g, '[^/]+');
  // Do not allow actix-style ":id" or "*" wildcard in route patterns to avoid false positives.
  // debugLog('actixPatternMatches', { routePattern, path, regex: reStr });
  const re = new RegExp('^' + reStr + '$');
  // debugLog('actixPatternMatches', { routePattern, path, regex: re.toString(), test: re.test(p) });
  return re.test(p);
}

// Get the last non-empty path segment from a URL or path.
function getLastPathSegment(path: string): string {
  if (!path) return '';
  let p = path;
  // strip query and fragment
  const qIdx = p.indexOf('?');
  if (qIdx >= 0) p = p.substring(0, qIdx);
  const hIdx = p.indexOf('#');
  if (hIdx >= 0) p = p.substring(0, hIdx);
  // strip protocol+host
  try {
    if (p.includes('://')) {
      const u = new URL(p);
      p = u.pathname;
    }
  } catch (_e) {
    // ignore URL parse errors
  }
  p = p.replace(/\/$/, '');
  const idx = p.lastIndexOf('/');
  const seg = idx >= 0 ? p.substring(idx + 1) : p;
  return seg ? ('/' + seg) : '/';
}

// Heuristic: ensure segment at index is not inside an identifier or module path
function isPotentialPathMatch(line: string, idx: number, segment: string): boolean {
  const segLen = segment.length;
  const before = idx - 1 >= 0 ? line[idx - 1] : '';
  const after = idx + segLen < line.length ? line[idx + segLen] : '';
  // if preceded by '::', it's likely Rust module or function path (e.g., bcrypt::verify)
  if (before === ':' && idx - 2 >= 0 && line[idx - 2] === ':') return false;
  // don't match when character around is alphanumeric or underscore (part of identifier)
  const alnum = /[A-Za-z0-9_]/;
  if (alnum.test(before) || alnum.test(after)) return false;
  return true;
}

// Returns true if the position is inside a line/block comment (best-effort)
function isInComment(line: string, idx: number): boolean {
  // Check for line comments '//' or '#' (for python)
  const slashPos = line.indexOf('//');
  if (slashPos !== -1 && slashPos < idx && (slashPos === 0 || line[slashPos - 1] !== ':')) {
    return true;
  }
  const hashPos = line.indexOf('#');
  if (hashPos !== -1 && hashPos < idx) {
    return true;
  }
  // Check for block comment start '/*' and no close '*/' before idx in same line
  const openPos = line.lastIndexOf('/*', idx);
  const closePos = line.lastIndexOf('*/', idx);
  if (openPos !== -1 && openPos > closePos) {
    return true;
  }
  return false;
}

// Return true if the character at idx (start of token) is inside a double or single-quoted string on the same line
function isInsideString(line: string, idx: number): boolean {
  // check double quotes
  const beforeDouble = line.lastIndexOf('"', idx - 1);
  const afterDouble = line.indexOf('"', idx + 1);
  if (beforeDouble !== -1 && afterDouble !== -1 && beforeDouble < afterDouble) return true;
  // check single quotes
  const beforeSingle = line.lastIndexOf("'", idx - 1);
  const afterSingle = line.indexOf("'", idx + 1);
  if (beforeSingle !== -1 && afterSingle !== -1 && beforeSingle < afterSingle) return true;
  return false;
}

// Return string boundaries (start idx, end idx, quote char) if idx is inside a string on the line
function getStringBounds(line: string, idx: number): { start: number; end: number; quoteChar: string } | null {
  const single = line.lastIndexOf("'", idx);
  const double = line.lastIndexOf('"', idx);
  let lastQuote = single > double ? single : double;
  let quoteChar = single > double ? "'" : '"';
  if (lastQuote === -1) return null;
  const nextQuote = line.indexOf(quoteChar, idx + 1);
  if (nextQuote === -1) return null;
  return { start: lastQuote, end: nextQuote, quoteChar };
}

// Detect if the index is inside a quoted string that contains a URL scheme (e.g., 'http://')
function isWithinAbsoluteUrl(line: string, idx: number): boolean {
  const bounds = getStringBounds(line, idx);
  if (!bounds) return false;
  const s = line.substring(bounds.start + 1, bounds.end);
  // Quick heuristic: contains '://' or starts with 'www.'
  if (s.includes('://')) return true;
  if (/^www\./i.test(s)) return true;
  return false;
}

// Detect if a route string contains only placeholder segments like '/{id}' or '/{bucket}/{...}'
function isGenericRoute(route: string): boolean {
  if (!route) return false;
  // Remove placeholder groups and slashes; if nothing remains, it's generic
  const cleaned = route.replace(/\{[^}]+\}/g, '').replace(/\//g, '');
  return cleaned.trim().length === 0;
}

// If a route's last segment is a placeholder like '/{bucket}' return true.
function isLastSegmentPlaceholder(route: string): boolean {
  if (!route) return false;
  // Normalize: ignore trailing slash
  const p = route.replace(/\/$/, '');
  return /\/\{[^\/}]+\}$/.test(p);
}

// Normalize a provided path or URL into a path starting with '/'.
function normalizeSearchPath(input: string): string {
  if (!input) return '/';
  let p = input.trim();
  // Strip surrounding quotes if present
  if ((p.startsWith("\"") && p.endsWith("\"")) || (p.startsWith("'") && p.endsWith("'"))) {
    p = p.substring(1, p.length - 1);
  }
  // Remove query and fragment
  const qIdx = p.indexOf('?');
  if (qIdx >= 0) p = p.substring(0, qIdx);
  const hIdx = p.indexOf('#');
  if (hIdx >= 0) p = p.substring(0, hIdx);
  // If contains protocol or host, use URL parsing
  try {
    if (p.includes('://')) {
      const u = new URL(p);
      p = u.pathname;
    }
  } catch (_e) {
    // ignore
  }
  // Ensure leading slash
  if (!p.startsWith('/')) p = '/' + p;
  // Remove trailing slash (except root)
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p;
}
