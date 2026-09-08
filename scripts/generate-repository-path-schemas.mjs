#!/usr/bin/env node
import {readFileSync,writeFileSync} from "node:fs";
import {createHash} from "node:crypto";
const root=new URL("../schemas/",import.meta.url);
const repositoryPath={type:"string",minLength:1,maxLength:512,pattern:"^[^\\u0000-\\u001f\\u007f-\\u009f\\\\:]+$"};
const outputs=[];
for(const [stem,kind] of [["work-contract","work-contract"],["compiled-policy-plan","compiled-policy-plan"],["promotion-receipt","promotion-receipt"]]){
 const value=JSON.parse(readFileSync(new URL(`${stem}-v2.schema.json`,root),"utf8"));
 const name=`${stem}-v3.schema.json`;
 value.$id=`https://raw.githubusercontent.com/Shedu-ai/shedu-promotion-kernel/main/schemas/${name}`;
 value.title=`${kind}@3`;value.properties.schemaVersion.const=`${kind}@3`;
 if(stem!=="compiled-policy-plan")value.$defs.repositoryPath=repositoryPath;
 if(stem==="work-contract")value.$defs.pathSet.items={$ref:"#/$defs/repositoryPath"};
 if(stem==="promotion-receipt")value.properties.changedFiles.items.properties.path={$ref:"#/$defs/repositoryPath"};
 const bytes=Buffer.from(JSON.stringify(value,null,2)+"\n");writeFileSync(new URL(name,root),bytes);
 outputs.push({path:name,digest:"sha256:"+createHash("sha256").update(bytes).digest("hex")});
}
console.log(JSON.stringify({schemaVersion:"repository-path-schema-generation@1",outputs}));
