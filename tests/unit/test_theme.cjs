const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const init = fs.readFileSync('app/public/theme-init.js', 'utf8');
const runtime = fs.readFileSync('app/public/theme.js', 'utf8');
function run(saved, dark, blocked=false) {
  const root = { dataset: {} };
  const listeners = {};
  const media = {matches: dark, addEventListener(name, fn) {listeners['media:'+name] = fn;}};
  const storage = {values: {...saved}, getItem(k) {if (blocked) throw Error('blocked'); return this.values[k] ?? null;}, setItem(k,v) {if (blocked) throw Error('blocked'); this.values[k]=v;}};
  const preference = {value: ''};
  const button = {attrs:{}, setAttribute(k,v){this.attrs[k]=v;}};
  const document = {documentElement: root, querySelectorAll(sel){return sel==='[data-theme-preference]'?[preference]:sel==='[data-theme-toggle]'?[button]:[];}, addEventListener(type, fn){(listeners[type]??=[]).push(fn);}};
  const ctx={document, localStorage:storage, matchMedia(){return media;}};
  vm.runInNewContext(init,ctx); const before={...root.dataset};
  vm.runInNewContext(runtime,ctx);
  return {root, before, media, storage, preference, listeners};
}
for (const dark of [false,true]) {
  let t=run({},dark); assert.equal(t.before.theme,'light'); assert.equal(t.root.dataset.theme,'light'); assert.equal(t.preference.value,'light');
  t=run({},dark,true); assert.equal(t.root.dataset.theme,'light');
  t=run({theme:'dark'},dark); assert.equal(t.root.dataset.theme,'dark');
  t=run({theme:'light'},dark); assert.equal(t.root.dataset.theme,'light');
  t=run({theme:'system'},dark); assert.equal(t.root.dataset.theme,dark?'dark':'light');
  t.media.matches=!dark; t.listeners['media:change'](); assert.equal(t.root.dataset.theme,dark?'light':'dark');
  t=run({theme:'invalid','pxe.sidebar.collapsed':'true'},dark); assert.equal(t.root.dataset.theme,'light'); assert.equal(t.root.dataset.sidebarCollapsed,'true');
}
const t=run({},false);
t.listeners.change[0]({target:{matches:()=>true,value:'dark'}});
assert.equal(t.root.dataset.theme,'dark'); assert.equal(t.storage.values.theme,'dark');
console.log('Theme initialization, stored preferences, system changes and storage failures: OK');
