// This closure is created before candidate evaluation. Its handle is held only
// by the native worker; nothing is installed into the candidate global object.
// It captures observations, never expected values, assertions or verdicts.
import {closed,decodeValue} from './behavioral-data.mjs';
export const OBSERVER_SOURCE = `(() => {
 ${closed.toString()}
 ${decodeValue.toString()}
 const ownKeys=Reflect.ownKeys, descriptor=Object.getOwnPropertyDescriptor, proto=Object.getPrototypeOf;
 const isArray=Array.isArray, setProto=Object.setPrototypeOf, hasOwn=Object.hasOwn, is=Object.is;
 const stringify=JSON.stringify, parse=JSON.parse, toString=String, apply=Reflect.apply, Failure=Error;
 const objectProto=Object.prototype, arrayProto=Array.prototype;
 const weakHas=WeakMap.prototype.has, weakGet=WeakMap.prototype.get, weakSet=WeakMap.prototype.set;
 const setHas=Set.prototype.has, setAdd=Set.prototype.add, Seen=Set;
 // Proxies can lie to property inspection; they are outside this fixture domain.
 Object.defineProperty(globalThis, "Proxy", {value:undefined,writable:false,configurable:false});
 const refs=new WeakMap(); let nextId=0;
 // Private containers have no candidate-visible prototypes. Never call shared
 // methods, iterators, toJSON or instanceof hooks after candidate evaluation.
 // Freezing shared intrinsics changes ordinary assignment semantics (e.g. an
 // own constructor property), so integrity comes from captured operations.
 function list(...items) { return setProto(items,null); }
 const errorNames=list('Error','TypeError','RangeError','SyntaxError');
 const errorProtos=list(Error.prototype,TypeError.prototype,RangeError.prototype,SyntaxError.prototype);
 function encode(value) {
  if(value===null)return 'null';
  if(typeof value!=='object')return stringify(value);
  let text='[';
  for(let i=0;i<value.length;i++)text+=(i?',':'')+encode(value[i]);
  return text+']';
 }
 function graph(roots) {
  const nodes=list(),seen=new Seen();let properties=0;
  function visit(value,depth) {
   if(depth>64)throw Failure('observation depth exceeded');
   if(value===null)return list('null');
   const type=typeof value;
   if(type==='undefined')return list('undefined');
   if(type==='boolean'||type==='string')return list(type,value);
   if(type==='number')return list(type,is(value,-0)?'-0':toString(value));
   if(type==='bigint')return list(type,toString(value));
   if(type!=='object')throw Failure('unsupported observation value');
   const p=proto(value);const kind=isArray(value)?'array':p===objectProto?'object':p===null?'null':null;
   if(kind===null || (kind==='array' && p!==arrayProto))throw Failure('unsupported observation prototype');
   if(!apply(weakHas,refs,list(value)))apply(weakSet,refs,list(value,nextId++));
   const id=apply(weakGet,refs,list(value));
   if(!apply(setHas,seen,list(id))) {
    if(nodes.length>=10000)throw Failure('observation node limit exceeded');
    apply(setAdd,seen,list(id));const props=list();nodes[nodes.length]=list(id,kind,props);
    const keys=ownKeys(value);
    for(let i=0;i<keys.length;i++) {
     const key=keys[i];
     if(typeof key!=='string'||++properties>50000)throw Failure('unsupported or excessive properties');
     const d=descriptor(value,key);if(!d || !hasOwn(d,'value'))throw Failure('accessors are outside the fixture domain');
     props[props.length]=list(key,d.enumerable,d.writable,d.configurable,visit(d.value,depth+1));
    }
   }
   return list('ref',id);
  }
  const values=list();for(let i=0;i<roots.length;i++)values[values.length]=visit(roots[i],0);
  // Only fixed field names and privately constructed arrays enter this encoder.
  return '{"roots":'+encode(values)+',"nodes":'+encode(nodes)+'}';
 }
 return {
  prepare: text=>decodeValue(parse(text)),
  before: args=>graph(args),
  after: (args,value)=>{const roots=list();for(let i=0;i<args.length;i++)roots[roots.length]=args[i];roots[roots.length]=value;return graph(roots);},
  exception: value=>{
   const names=list();let p=value;
   // Prototype inspection bypasses candidate Symbol.hasInstance implementations.
   for(let depth=0;p!==null && (typeof p==='object'||typeof p==='function');depth++) {
    if(depth>64)throw Failure('exception prototype depth exceeded');
    p=proto(p);
    for(let i=0;i<errorProtos.length;i++)if(p===errorProtos[i])names[names.length]=errorNames[i];
   }
   return encode(names);
  }
 };
})()`;
