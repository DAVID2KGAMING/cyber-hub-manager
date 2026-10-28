// Checks declared layout bounds and real UI transitions. Happy DOM is not a
// rendering engine: these assertions must not be reported as a screenshot test.
const fs=require('fs'),path=require('path'),assert=require('assert');
(async()=>{
 const {Window}=await import(process.env.HAPPY_DOM_PATH||path.resolve(__dirname,'../../toolchain/test-node/node_modules/happy-dom/lib/index.js'));
 const w=new Window({url:'https://appassets.androidplatform.net/assets/app.html',width:360,height:694,settings:{disableJavaScriptFileLoading:true,disableCSSFileLoading:true}});
 const assets=path.resolve(__dirname,'../app/src/main/assets');
 const read=name=>fs.readFileSync(path.join(process.env.UI_ASSETS_PATH&&['app.js','style.css'].includes(name)?process.env.UI_ASSETS_PATH:assets,name),'utf8');
 w.document.write(read('app.html').replace(/<script[^>]*>[\s\S]*?<\/script>/g,'').replace(/<link[^>]*>/g,''));
 for(const name of ['vendor/codemirror.css','style.css']){const style=w.document.createElement('style');style.textContent=read(name);w.document.head.append(style);}
 const errors=[];w.addEventListener('error',e=>errors.push(e.message));w.console.error=(...a)=>errors.push(a.join(' '));
 const source=fs.readFileSync(path.join(__dirname,'ui-smoke.cjs'),'utf8');
 const a=source.indexOf('await page.addInitScript(()=>{')+'await page.addInitScript(()=>{'.length,b=source.indexOf('});const url=',a);w.eval(source.slice(a,b));
 const native=w.CyberNative.request;
 w.CyberNative.request=(id,action,json)=>{
  const args=JSON.parse(json);
  if(action!=='dexTree')return native(id,action,json);
  const data=args.prefix==='com/'?[{name:'cyberalpha.stringtobyte',prefix:'com/cyberalpha/stringtobyte/',dir:true},{name:'other',prefix:'com/other/',dir:true}]:args.prefix?[{name:'MainActivity',class:'Lcom/cyberhub/example/MainActivity;',dir:false}]:[{name:'android.net',prefix:'android/net/',dir:true},{name:'com',prefix:'com/',dir:true},{name:'org.apache',prefix:'org/apache/',dir:true}];
  setTimeout(()=>w.receive({id,ok:true,data}),2);
 };
 for(const name of ['boot.js','vendor/codemirror.js','vendor/clike.js','vendor/xml.js','vendor/searchcursor.js','app.js'])w.eval(read(name));
 const sleep=ms=>new Promise(r=>setTimeout(r,ms));
 async function until(fn){for(let n=0;n<80;n++){if(fn())return;await sleep(10);}throw Error('UI did not reach expected state');}
 const $=s=>w.document.querySelector(s),css=(s,k)=>w.getComputedStyle(typeof s==='string'?$(s):s)[k];
 function click(text,scope=w.document){const button=[...scope.querySelectorAll('button')].find(b=>b.getAttribute('aria-label')===text||b.textContent.trim()===text||b.querySelector('.filename')?.textContent===text||b.querySelector('.treename')?.textContent===text);assert(button,'Missing '+text);button.click();}
 let count=0;const pass=name=>{count++;console.log('PASS '+name);};
 function boundedIcons(){for(const svg of w.document.querySelectorAll('svg')){assert(+svg.getAttribute('width')>0&&+svg.getAttribute('width')<=28,'SVG intrinsic width');assert(+svg.getAttribute('height')>0&&+svg.getAttribute('height')<=28,'SVG intrinsic height');assert(parseFloat(w.getComputedStyle(svg).width)<=28,'SVG computed width');}}
 await until(()=>$('.pane .file'));
 boundedIcons();assert.equal(css('#toolbar','height'),'56px');assert.equal(css('#bottom','height'),'46px');pass('toolbar, navigation and all SVGs have reference-size bounds');
 assert.equal(css('.file','minHeight'),'40px');assert.equal(css('.fileicon','width'),'28px');assert.equal(css('.filemeta','display'),'block');pass('compact file rows, filled folders and stacked metadata');
 const left=$('.pane');left.scrollTop=160;left.dispatchEvent(new w.Event('scroll'));
 click('sample.apk',left);await until(()=>$('.apkDialog'));
 assert.equal(css('.apkHead','height'),'48px');assert.equal(css('.apkHead h2','whiteSpace'),'nowrap');assert.equal(css('.dataGrid .value','textOverflow'),'ellipsis');assert.equal($('.apkDialog .actions').children.length,3);pass('APK title/icon and metadata remain bounded with three actions');
 click('View');await until(()=>left.isConnected===false&&$('.pane').textContent.includes('classes.dex'));
 click('classes.dex',$('.pane'));await until(()=>$('.multidexDialog'));
 assert.equal(css('.multidexDialog .actions','flexDirection'),'column');assert.equal(css('.multidexDialog .actions button','height'),'48px');assert.equal(css('.checkrow input','width'),'18px');pass('MultiDex uses stacked actions and reference-size checkboxes');
 click('OK');await until(()=>$('.treeRow'));assert.equal(css('.treeRow','height'),'33px');assert.equal(css('.tabs','height'),'48px');assert(!$('.breadcrumbs'));pass('DEX root uses compact rows without an oversized parent row');
 click('com');await until(()=>$('.treeChildren .treeRow'));assert.equal($('[data-prefix="com/"]').getAttribute('aria-expanded'),'true');assert([...w.document.querySelectorAll('.treename')].some(n=>n.textContent==='android.net'));pass('package expansion retains root siblings');
 click('cyberalpha.stringtobyte');await until(()=>$('.classicon'));assert.equal($('[data-prefix="com/cyberalpha/stringtobyte/"]').getAttribute('aria-expanded'),'true');boundedIcons();pass('nested package expansion has bounded chevrons and class icons');
 click('MainActivity');await until(()=>$('.CodeMirror'));assert.equal(css('.CodeMirror','fontSize'),'14px');pass('Smali starts at the reference reading scale');
 click('Editor menu');click('View Java');await until(()=>$('.javaEditor'));assert.equal(css('.CodeMirror','fontSize'),'6px');click('Editor menu');assert.equal(css('.overflowMenu','width'),'196px');assert.equal(css('[role="menuitem"]','minHeight'),'48px');boundedIcons();pass('Java viewer and eight-action menu have explicit dimensions');
 await w.goBack();await w.goBack();await until(()=>$('.tree'));assert.equal($('[data-prefix="com/"]').getAttribute('aria-expanded'),'true');assert.equal($('[data-prefix="com/cyberalpha/stringtobyte/"]').getAttribute('aria-expanded'),'true');pass('returning from the editor preserves expanded branches');
 click('com');assert($('[data-prefix="com/"]').nextElementSibling.hidden);click('com');await until(()=>!$('[data-prefix="com/"]').nextElementSibling.hidden);assert($('.classicon'));pass('collapse and reopen retain child state');
 click('Open navigation');await until(()=>$('[data-group="toolRows"]'));click('Tools');assert($('#toolRows').hidden);click('Tools');assert(!$('#toolRows').hidden);assert.equal(css('.drawerRow','minHeight'),'40px');boundedIcons();pass('drawer groups collapse and use compact rows');
 assert.deepEqual(errors,[]);pass('no JavaScript errors during nested navigation');
 console.log('ALL '+count+' LAYOUT/INTERACTION CHECKS PASSED (computed CSS, not rendered pixels)');await w.happyDOM.close();
})().catch(e=>{console.error(e);process.exit(1)});
