/* CborLens engine: decode CBOR (RFC 8949) with canonicality analysis.
   All major types, definite + indefinite lengths, tags, half/float32/64,
   BigInt for 64-bit ints. No dependencies; browser + Node. */
(function(root,factory){
  if(typeof module==='object'&&module.exports){module.exports=factory();}
  else{root.CborLens=factory();}
})(typeof self!=='undefined'?self:this,function(){
'use strict';
function f16(h){
  var s=(h&0x8000)?-1:1,e=(h>>10)&0x1F,f=h&0x3FF;
  if(e===0)return s*Math.pow(2,-14)*(f/1024);
  if(e===31)return f?NaN:s*Infinity;
  return s*Math.pow(2,e-15)*(1+f/1024);
}
function parse(bytes){
  var r={errors:[],warnings:[],violations:[],items:0,max_depth:0,by_type:{}};
  var pos=0;
  function note(t){r.items++;r.by_type[t]=(r.by_type[t]||0)+1;}
  function u8(){if(pos>=bytes.length)throw {trunc:true};return bytes[pos++];}
  function take(n){if(pos+n>bytes.length)throw {trunc:true};var a=bytes.slice(pos,pos+n);pos+=n;return a;}
  function big(arr){var v=0n;for(var i=0;i<arr.length;i++)v=(v<<8n)|BigInt(arr[i]);return v;}
  function head(){
    var b=u8(),mt=b>>5,ai=b&31;
    var val=null,len=0,indef=false;
    if(ai<24){val=BigInt(ai);}
    else if(ai===24){var v1=u8();val=BigInt(v1);len=1;if(v1<24)r.violations.push('non-shortest integer encoding');}
    else if(ai===25){var a2=take(2);val=big(a2);len=2;if(a2[0]===0)r.violations.push('non-shortest integer encoding');}
    else if(ai===26){var a4=take(4);val=big(a4);len=4;if(a4[0]===0&&a4[1]===0)r.violations.push('non-shortest integer encoding');}
    else if(ai===27){var a8=take(8);val=big(a8);len=8;if(a8[0]===0&&a8[1]===0&&a8[2]===0&&a8[3]===0)r.violations.push('non-shortest integer encoding');}
    else if(ai===31){indef=true;}
    else throw {bad:'reserved additional info '+ai};
    return {mt:mt,ai:ai,val:val,hdr:1+len,indef:indef};
  }
  function textOf(arr){try{return new TextDecoder('utf-8',{fatal:true}).decode(arr);}catch(e){return null;}}
  function itemInner(depth){
    if(depth>r.max_depth)r.max_depth=depth;
    var start=pos;
    var h=head();
    var mt=h.mt;
    if(mt===0){note('uint');var n=h.val;var out={type:'uint',bytes:pos-start,hdr:h.hdr};
      out.value=n<=9007199254740991n?Number(n):n.toString();out.big=n>9007199254740991n;return out;}
    if(mt===1){note('nint');var m=h.val,out2={type:'nint',bytes:pos-start,hdr:h.hdr};
      var v=(-1n-m);out2.value=v>=-9007199254740991n?Number(v):v.toString();out2.big=v< -9007199254740991n;return out2;}
    if(mt===2||mt===3){
      var chunks=[],total=0;
      if(h.indef){r.violations.push('indefinite-length '+(mt===2?'byte':'text')+' string (not canonical)');
        for(;;){var c=head();
          if(c.mt===7&&c.ai===31)break;
          if(c.mt!==mt||c.indef)throw {bad:'bad chunk in indefinite string'};
          var cd=take(Number(c.val));chunks.push(cd);total+=cd.length;}
      }else{var d=take(Number(h.val));chunks=[d];total=d.length;}
      var all=new Uint8Array(total),off=0;
      for(var k=0;k<chunks.length;k++){all.set(chunks[k],off);off+=chunks[k].length;}
      if(mt===2){note('bytes');return {type:'bytes',length:total,bytes:pos-start,indef:h.indef,chunks:chunks.length,preview:Array.from(all.slice(0,8)).map(function(x){return x.toString(16).padStart(2,'0');}).join(' ')};}
      var t=textOf(all);
      if(t===null){r.warnings.push('invalid UTF-8 in text string');t='?invalid-utf8?';}
      note('text');return {type:'text',value:t.length>64?t.slice(0,64)+'...':t,length:total,bytes:pos-start,indef:h.indef,chunks:chunks.length};
    }
    if(mt===4){
      note('array');var arr=[];
      if(h.indef){r.violations.push('indefinite-length array (not canonical)');
        for(;;){if(pos>=bytes.length)throw {trunc:true};
          if(bytes[pos]===0xFF){pos++;break;}
          arr.push(item(depth+1));}
      }else{var n4=Number(h.val);for(var i4=0;i4<n4;i4++)arr.push(item(depth+1));}
      return {type:'array',length:arr.length,children:arr,bytes:pos-start,indef:h.indef};
    }
    if(mt===5){
      note('map');var pairs=[];
      if(h.indef){r.violations.push('indefinite-length map (not canonical)');
        for(;;){if(pos>=bytes.length)throw {trunc:true};
          if(bytes[pos]===0xFF){pos++;break;}
          pairs.push({key:item(depth+1),value:item(depth+1)});}
      }else{var n5=Number(h.val);
        for(var i5=0;i5<n5;i5++)pairs.push({key:item(depth+1),value:item(depth+1)});}
      var enc=pairs.map(function(p){return p.key._enc;});
      for(var s=1;s<enc.length;s++){
        var a=enc[s-1],b=enc[s];
        var shorter=a.length<=b.length?a:b;
        var cmp=0;
        for(var x=0;x<shorter.length;x++){if(a[x]!==b[x]){cmp=a[x]-b[x];break;}}
        if(cmp===0)cmp=a.length-b.length;
        if(cmp===0)r.warnings.push('duplicate map key');
        if(cmp>0)r.violations.push('map keys not in canonical order');
      }
      return {type:'map',length:pairs.length,children:pairs,bytes:pos-start,indef:h.indef};
    }
    if(mt===6){note('tag');var inner=item(depth+1);
      return {type:'tag',tag:Number(h.val),children:[inner],bytes:pos-start};}
    if(mt===7){
      if(h.ai===31)return {type:'break',bytes:pos-start};
      var simples={20:false,21:true,22:null,23:'undefined'};
      if(h.ai>=20&&h.ai<=23){note('simple');return {type:'simple',value:simples[h.ai],bytes:pos-start};}
      if(h.ai<20||h.ai===24){note('simple');return {type:'simple',value:Number(h.val),bytes:pos-start};}
      if(h.ai===25){note('float16');return {type:'float16',value:f16(Number(h.val)),bytes:pos-start};}
      if(h.ai===26){note('float32');var b4=bytes.slice(pos-4,pos);var dv=new DataView(new ArrayBuffer(4));for(var z=0;z<4;z++)dv.setUint8(z,b4[z]);
        return {type:'float32',value:dv.getFloat32(0),bytes:pos-start};}
      if(h.ai===27){note('float64');var b8=bytes.slice(pos-8,pos);var dv8=new DataView(new ArrayBuffer(8));for(var z8=0;z8<8;z8++)dv8.setUint8(z8,b8[z8]);
        return {type:'float64',value:dv8.getFloat64(0),bytes:pos-start};}
      throw {bad:'bad simple/float ai '+h.ai};
    }
    throw {bad:'impossible major type'};
  }
  function item(depth){
    var s0=pos;
    var out=itemInner(depth);
    out._enc=bytes.slice(s0,pos);
    return out;
  }
  try{
    var top=[];
    while(pos<bytes.length)top.push(item(1));
    r.top=top;
    r.canonical=r.violations.length===0;
    if(!top.length)r.warnings.push('empty input: no CBOR items');
  }catch(e){
    if(e&&e.trunc)r.errors.push('truncated: ran out of bytes');
    else if(e&&e.bad)r.errors.push(String(e.bad));
    else throw e;
  }
  return r;
}
return {parse:parse};
});
