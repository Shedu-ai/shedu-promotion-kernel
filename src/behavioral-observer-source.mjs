// This closure is created before candidate evaluation. Its handle is held only
// by the native worker; nothing is installed into the candidate global object.
// It captures observations, never expected values, assertions or verdicts.
import {closed,decodeValue} from './behavioral-data.mjs';
export const OBSERVER_SOURCE = `(() => {
 ${closed.toString()}
 ${decodeValue.toString()}
 const O=Object, S=Set; const ownKeys=Reflect.ownKeys, descriptor=Object.getOwnPropertyDescriptor, proto=Object.getPrototypeOf;
 const isArray=Array.isArray, create=Object.create, freeze=Object.freeze;
 const stringify=JSON.stringify, parse=JSON.parse, toString=String;
 const objectProto=Object.prototype, arrayProto=Array.prototype;
 const E={Error,TypeError,RangeError,SyntaxError};
 // Proxies can lie to property inspection; they are outside this fixture domain.
 O.defineProperty(globalThis, "Proxy", {value:undefined,writable:false,configurable:false});
 const refs=new WeakMap(); let nextId=0;
 const record=()=>create(null);
 // Freeze shared intrinsics to prevent candidate prototype hooks from altering
 // observation serialization. Candidate data objects remain mutable.
 const visited=new Set();
 function lock(value) {
  if((typeof value!=='object' && typeof value!=='function') || value===null || visited.has(value))return;
  visited.add(value);
  for(const key of ownKeys(value)) { const d=descriptor(value,key); if(d && 'value' in d)lock(d.value); }
  freeze(value);
 }
 for(const value of [Object,Array,Function,Number,String,Boolean,BigInt,Symbol,Map,Set,WeakMap,WeakSet,JSON,Reflect,Math,Date,RegExp,Promise,Error,TypeError,RangeError,SyntaxError])lock(value);
 function graph(roots) {
  const nodes=[],seen=new S();let properties=0;
  function visit(value,depth) {
   if(depth>64)throw Error('observation depth exceeded');
   if(value===null)return ['null'];
   const type=typeof value;
   if(type==='undefined')return ['undefined'];
   if(type==='boolean'||type==='string')return [type,value];
   if(type==='number')return [type,O.is(value,-0)?'-0':toString(value)];
   if(type==='bigint')return [type,toString(value)];
   if(type!=='object')throw Error('unsupported observation value');
   const p=proto(value);const kind=isArray(value)?'array':p===objectProto?'object':p===null?'null':null;
   if(kind===null || (kind==='array' && p!==arrayProto))throw Error('unsupported observation prototype');
   if(!refs.has(value))refs.set(value,nextId++);
   const id=refs.get(value);
   if(!seen.has(id)) {
    if(nodes.length>=10000)throw Error('observation node limit exceeded');
    seen.add(id);const props=[];nodes.push([id,kind,props]);
    for(const key of ownKeys(value)) {
     if(typeof key!=='string'||++properties>50000)throw Error('unsupported or excessive properties');
     const d=descriptor(value,key);if(!d || !('value' in d))throw Error('accessors are outside the fixture domain');
     props.push([key,d.enumerable,d.writable,d.configurable,visit(d.value,depth+1)]);
    }
   }
   return ['ref',id];
  }
  const values=[];for(let i=0;i<roots.length;i++)values.push(visit(roots[i],0));
  const result=record();result.roots=values;result.nodes=nodes;return result;
 }
 return {
  prepare: text=>decodeValue(parse(text)),
  before: args=>stringify(graph(args)),
  after: (args,value)=>{const roots=[];for(let i=0;i<args.length;i++)roots.push(args[i]);roots.push(value);return stringify(graph(roots));},
  exception: value=>stringify(O.keys(E).filter(name=>value instanceof E[name]))
 };
})()`;
