// Counts actual editor work. Happy DOM cannot measure device FPS or paint time.
const fs=require('fs'),path=require('path'),assert=require('assert');
(async()=>{
 const {Window}=await import(process.env.HAPPY_DOM_PATH||path.resolve(__dirname,'../../toolchain/test-node/node_modules/happy-dom/lib/index.js'));
 const w=new Window({url:'https://appassets.androidplatform.net/assets/app.html',width:398,height:768,settings:{disableJavaScriptFileLoading:true,disableCSSFileLoading:true}});
 const assets=path.resolve(__dirname,'../app/src/main/assets'),sleep=ms=>new Promise(r=>setTimeout(r,ms));
 w.console.warn=()=>{};w.document.write(fs.readFileSync(path.join(assets,'app.html'),'utf8').replace(/<script[^>]*>[\s\S]*?<\/script>/g,'').replace(/<link[^>]*>/g,''));
 const mock=fs.readFileSync(path.join(__dirname,'ui-smoke.cjs'),'utf8'),start=mock.indexOf('await page.addInitScript(()=>{')+'await page.addInitScript(()=>{'.length,end=mock.indexOf('});const url=',start);w.eval(mock.slice(start,end));
 const longText='.class public Ldemo/Large;\n.super Ljava/lang/Object;\n'+Array.from({length:3000},(_,i)=>'.method public static m'+i+'()V\n.registers 1\nconst-string v0, "sample"\nreturn-void\n.end method\n').join('');
 const native=w.CyberNative.request;w.CyberNative.request=(id,action,raw)=>{if(action!=='dexCode')return native(id,action,raw);setTimeout(()=>w.receive({id,ok:true,data:{class:'Ldemo/Large;',mode:'smali',name:'Large.smali',text:longText}}),1);};
 for(const file of ['boot.js','vendor/codemirror.js','vendor/clike.js','vendor/xml.js','vendor/searchcursor.js','app.js'])w.eval(fs.readFileSync(file==='app.js'&&process.env.UI_SCRIPT?process.env.UI_SCRIPT:path.join(assets,file),'utf8').replace('\ninit();','\nwindow.__test={state,openClass,openDrawer,closeDrawer};\ninit();'));
 await sleep(60);const t=w.__test;await t.openClass('Ldemo/Large;','smali');await sleep(150);
 const cm=t.state.cm;let fullBufferReads=0,refreshes=0,lineVisits=0;
 for(const name of ['getValue','refresh','eachLine']){const original=cm[name];cm[name]=function(...a){if(name==='getValue')fullBufferReads++;if(name==='refresh')refreshes++;if(name==='eachLine'){const cb=a[a.length-1];a[a.length-1]=(...args)=>{lineVisits++;return cb(...args);};}return original.apply(this,a);};}
 const startTyping=performance.now();for(let i=0;i<30;i++){cm.replaceRange('x',{line:2,ch:0});await sleep(5);}await sleep(180);const typingMs=performance.now()-startTyping;
 function touch(type,pts){const e=new w.Event(type,{bubbles:true,cancelable:true});Object.defineProperty(e,'touches',{value:pts.map(([x,y,id])=>({clientX:x,clientY:y,pageX:x,pageY:y,identifier:id}))});cm.getScrollerElement().dispatchEvent(e);}
 refreshes=0;touch('touchstart',[[100,250,1],[200,250,2]]);for(let i=0;i<30;i++){touch('touchmove',[[100,250,1],[200+i*2,250,2]]);await sleep(18);}const refreshesDuringPinch=refreshes;touch('touchend',[]);
 const result={label:process.env.UI_SCRIPT?'0.1.4 baseline':'0.1.5',lines:cm.lineCount(),edits:30,fullBufferReadsDuringTyping:fullBufferReads,fullLineVisitsDuringTyping:lineVisits,typingHarnessMs:Math.round(typingMs),pinchMoves:30,refreshesDuringPinch,refreshesIncludingRelease:refreshes,environment:'Synthetic touch / Happy DOM. No paint, GPU, Android runtime or FPS measurement.'};
 console.log(JSON.stringify(result,null,2));
 if(!process.env.UI_SCRIPT){assert.equal(fullBufferReads,0);assert.equal(lineVisits,0);assert.equal(refreshesDuringPinch,0);assert.equal(refreshes,1);}
 await w.happyDOM.close();
})().catch(e=>{console.error(e);process.exit(1)});
