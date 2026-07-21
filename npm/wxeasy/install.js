#!/usr/bin/env node
'use strict';

const fs = require('fs');

const PLATFORM_PACKAGES = {
  'darwin-arm64': 'wxeasy-darwin-arm64',
  'darwin-x64':   'wxeasy-darwin-x64',
  'linux-x64':    'wxeasy-linux-x64',
  'linux-arm64':  'wxeasy-linux-arm64',
  'win32-x64':    'wxeasy-win32-x64',
};

const platformKey = `${process.platform}-${process.arch}`;
const pkg = PLATFORM_PACKAGES[platformKey];

if (!pkg) {
  console.log(`wxeasy: no binary for ${platformKey}, skipping`);
  process.exit(0);
}

const ext = process.platform === 'win32' ? '.exe' : '';

try {
  const binaryPath = require.resolve(`${pkg}/bin/wxeasy${ext}`);
  if (process.platform !== 'win32') {
    fs.chmodSync(binaryPath, 0o755);
  }
} catch {
  console.log(`wxeasy: platform package ${pkg} not installed`);
}
