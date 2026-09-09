#!/usr/bin/env node
// Rebuild from the exact lockfile. No package lifecycle scripts run.
import {mkdtempSync,readFileSync,writeFileSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const vendor=new URL('../vendor/quickjs/',import.meta.url);
const lock=JSON.parse(readFileSync(new URL('build-lock.json',vendor)));
const dir=mkdtempSync(join(tmpdir(),'shedu-runtime-build-'));
writeFileSync(join(dir,'package.json'),JSON.stringify({private:true,dependencies:lock.packages[''].dependencies}));
copyFileSync(new URL('build-lock.json',vendor),join(dir,'package-lock.json'));
execFileSync('npm',['ci','--ignore-scripts','--no-audit','--no-fund'],{cwd:dir,stdio:'inherit'});
writeFileSync(join(dir,'entry.mjs'),"import {newQuickJSWASMModuleFromVariant} from 'quickjs-emscripten-core';\nimport variant from '@jitl/quickjs-singlefile-cjs-release-sync';\nexport function createEngine() { return newQuickJSWASMModuleFromVariant(variant); }\n");
execFileSync(process.execPath,['--input-type=module','-e',"import {build} from 'esbuild';await build({entryPoints:['entry.mjs'],outfile:'runtime.cjs',bundle:true,platform:'node',format:'cjs',target:'node22',legalComments:'eof'});"],{cwd:dir,stdio:'inherit'});
const bytes=readFileSync(join(dir,'runtime.cjs')),digest=createHash('sha256').update(bytes).digest('hex');
const expected=JSON.parse(readFileSync(new URL('provenance.json',vendor))).bundleSHA256;
if(digest!==expected)throw Error(`rebuild differs: ${digest}`);
console.log(JSON.stringify({reproduced:true,sha256:digest,bytes:bytes.length}));
