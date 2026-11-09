import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, cpSync, rmSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

if (!process.env.SCIM_THEME_BUILD_DIRECTORY || !process.env.SCIM_THEME_OUTPUT_DIRECTORY) {
  throw new Error('Build the admin theme through mvn package to configure its output directories.');
}
const buildDirectory = resolve(process.env.SCIM_THEME_BUILD_DIRECTORY);
const outputDirectory = resolve(process.env.SCIM_THEME_OUTPUT_DIRECTORY);
const localSource = dirname(fileURLToPath(import.meta.url));
// The theme patch is deliberately tied to the server's exact upstream revision.
const revision = '24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b'; // Keycloak 26.8.1
const source = resolve(buildDirectory, 'keycloak-admin-source');
rmSync(source, { recursive: true, force: true });
mkdirSync(source, { recursive: true });
const archive = resolve(buildDirectory, 'keycloak-admin-source.tar.gz');
const response = await fetch(`https://codeload.github.com/keycloak/keycloak/tar.gz/${revision}`);
if (!response.ok) throw new Error(`Source download failed: ${response.status}`);
writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
execFileSync('tar', ['-xzf', archive, '--strip-components=1', '-C', source]);
const target = `${source}/js/apps/admin-ui/src/user-federation/custom/CustomProviderSettings.tsx`;
let code = readFileSync(target, 'utf8');
const marker = '          <ActionGroup>';
if (!code.includes(marker)) throw new Error('Upstream provider form changed; review the SCIM patch');
code = 'import { ScimConnectionTest } from "./ScimConnectionTest";\n' + code.replace(marker,
  '          {providerId === "keycloak-scim-outbound" && <ScimConnectionTest componentId={id} isDirty={isDirty} />}\n' + marker);
writeFileSync(target, code);
cpSync(resolve(localSource, 'ScimConnectionTest.tsx'), `${source}/js/apps/admin-ui/src/user-federation/custom/ScimConnectionTest.tsx`);
const cwd = `${source}/js`;
execFileSync('pnpm', ['install', '--frozen-lockfile', '--ignore-scripts'], { cwd, stdio: 'inherit' });
execFileSync('pnpm', ['--filter', '@keycloak/keycloak-admin-ui', 'build'], { cwd, stdio: 'inherit' });
const theme = resolve(outputDirectory, 'theme/scim-outbound/admin');
rmSync(theme, { recursive: true, force: true });
mkdirSync(theme, { recursive: true });
writeFileSync(`${theme}/theme.properties`, 'parent=keycloak.v2\ndarkMode=true\nkcDarkModeClass=pf-v5-theme-dark\ncontentHashPattern=assets/.*/*\n');
cpSync(`${source}/js/apps/admin-ui/target/classes/theme/keycloak.v2/admin/resources`, `${theme}/resources`, { recursive: true });
