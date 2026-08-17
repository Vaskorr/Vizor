import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the Vizor operations console", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Vizor — мониторинг сети<\/title>/i);
  assert.match(html, /VIZOR/);
  assert.match(html, /Обзор сети/);
  assert.match(html, /Запустить скан/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("ships the requested Nmap workflows", async () => {
  const [page, layout, packageJson, dockerfile, backend] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../Dockerfile", import.meta.url), "utf8"),
    readFile(new URL("../server/main.py", import.meta.url), "utf8"),
  ]);

  assert.match(page, /DOMParser/);
  assert.match(page, /\/api\/scans\/run/);
  assert.match(page, /\/api\/reports\/changes\.pdf/);
  assert.match(page, /NSE-скрипт/);
  assert.match(layout, /Vizor — мониторинг сети/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.match(dockerfile, /apt-get install[^\n]*nmap/);
  assert.match(backend, /subprocess\.run\(\s*command/);
  assert.match(backend, /SAFE_NMAP_SWITCHES/);
  assert.match(backend, /shell=False/);
  assert.match(backend, /CREATE TABLE IF NOT EXISTS scripts/);
  assert.doesNotMatch(backend, /shell\s*=\s*True/);
});
