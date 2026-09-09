#!/usr/bin/env node
// Convenience CLI; promotion policies must use behavioral-cases-verify@1.
// Never copy this wrapper into candidate/base code and treat its stdout as authority.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runCases} from '../src/behavioral-parent.mjs';
export {runCases} from '../src/behavioral-parent.mjs';
export {decodeValue,validateCases} from '../src/behavioral-data.mjs';
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 const [casesPath,candidatePath=process.env.KERNEL_CANDIDATE_DIR]=process.argv.slice(2);
 if(!casesPath||!candidatePath)throw Error('usage: behavioral-check.mjs CASES_JSON CANDIDATE_DIR');
 const report=runCases(JSON.parse(readFileSync(casesPath,'utf8')),resolve(candidatePath));
 process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=report.status==='PASS'?0:1;
}
