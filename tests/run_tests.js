/* CborLens tests: shared engine over the corpus vs tests/expected.json
   (independent python CBOR decoder oracle). */
'use strict';
const fs=require('fs'),path=require('path');
const engine=require(path.join(__dirname,'..','engine.js'));
const items=JSON.parse(fs.readFileSync(path.join(__dirname,'expected.json'),'utf8')).items;
let fail=0,pass=0;
function ok(l){pass++;}
function bad(l,a,b){fail++;console.log('FAIL '+l+': got '+JSON.stringify(a)+' want '+JSON.stringify(b));}
function numeq(a,b){ // tolerate float repr + bigint string forms + specials
  if(a===b)return true;
  if(typeof a==='number'&&typeof b==='number')return Math.abs(a-b)<=1e-6*Math.max(1,Math.abs(b));
  return String(a)===String(b);
}
function cmpTree(got,want,label){
  if(!Array.isArray(want))return bad(label+' shape',got,want);
  const t=want[0];
  if(got.type!==t&&!(t==='float16'&&got.type==='float16'))return bad(label+'.type',got.type,t);
  switch(t){
    case 'uint': case 'nint':
      if(numeq(got.value,want[1]))ok(label);else bad(label+'.value',got.value,want[1]);break;
    case 'text':
      if(got.value===want[1]||(want[1].length>64&&got.value===want[1].slice(0,64)+'...'))ok(label);else bad(label+'.text',got.value,want[1]);break;
    case 'bytes':
      if(got.length===want[1].length/2&&want[1].startsWith(got.preview.replace(/ /g,'')))ok(label);else bad(label+'.bytes',got,want[1]);break;
    case 'simple':
      if(got.value===want[1]||String(got.value)===String(want[1]))ok(label);else bad(label+'.simple',got.value,want[1]);break;
    case 'float16': case 'float32': case 'float64':
      if(numeq(got.value,want[1]))ok(label);else bad(label+'.float',got.value,want[1]);break;
    case 'array':
      if(got.children.length!==want[1].length)return bad(label+'.array len',got.children.length,want[1].length);
      ok(label);
      want[1].forEach((w,i)=>cmpTree(got.children[i],w,label+'['+i+']'));
      break;
    case 'map':
      if(got.children.length!==want[1].length)return bad(label+'.map len',got.children.length,want[1].length);
      ok(label);
      want[1].forEach((w,i)=>{cmpTree(got.children[i].key,w[0],label+'.k'+i);cmpTree(got.children[i].value,w[1],label+'.v'+i);});
      break;
    case 'tag':
      if(got.tag!==want[1])return bad(label+'.tag',got.tag,want[1]);
      ok(label);
      cmpTree(got.children[0],want[2],label+'.inner');
      break;
    default: bad(label+' unknown oracle type '+t,got,want);
  }
}
for(const item of items){
  const rawPath=path.join(__dirname,'corpus',item.file);
  const bytes=fs.existsSync(rawPath)
    ? new Uint8Array(fs.readFileSync(rawPath))
    : new Uint8Array(Buffer.from(fs.readFileSync(rawPath+'.b64','utf8').trim(),'base64'));
  const r=engine.parse(bytes);
  const T=item.file+' ';
  if(item.expect_error){
    if(r.errors.some(e=>e.indexOf(item.expect_error)>=0))pass++;
    else{fail++;console.log('FAIL '+T+'missing error got '+JSON.stringify(r.errors));}
    continue;
  }
  const o=item.oracle;
  if(r.errors.length)bad(T+'errors',r.errors,0);else pass++;
  if(r.items!==o.items)bad(T+'items',r.items,o.items);else pass++;
  if(r.max_depth!==o.max_depth)bad(T+'max_depth',r.max_depth,o.max_depth);else pass++;
  if(r.canonical!==o.canonical)bad(T+'canonical',r.canonical,o.canonical);else pass++;
  if(r.violations.length!==o.violations.length)bad(T+'violations',r.violations,o.violations);else pass++;
  if(r.warnings.length!==o.warnings.length)bad(T+'warnings',r.warnings,o.warnings);else pass++;
  if(r.top.length!==o.top.length)bad(T+'top len',r.top.length,o.top.length);
  else o.top.forEach((w,i)=>cmpTree(r.top[i],w,T+'top['+i+']'));
}
console.log(pass+' passed, '+fail+' failed');
process.exit(fail?1:0);
