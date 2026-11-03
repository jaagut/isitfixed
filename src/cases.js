export function hasCaseUpdate(state,c) {
  return Boolean(c.hasUpdate || state.activity.some(a=>a.id===c.id&&a.unread));
}
export function recordUpdate(state,id,text,time=Date.now()) {
  const c=state.cases.find(c=>c.id===id);
  if(c){c.updatedAt=time;c.hasUpdate=true;}
  state.activity.unshift({id,text,time,unread:true});
  state.activity=state.activity.slice(0,100);
}
export function markCaseRead(state,id) {
  const c=state.cases.find(c=>c.id===id);
  if(c)c.hasUpdate=false;
  state.activity.filter(a=>a.id===id).forEach(a=>a.unread=false);
}
export function sortedCases(state) {
  const latest=c=>Math.max(c.updatedAt||0,c.created||0,...state.activity.filter(a=>a.id===c.id).map(a=>a.time||0));
  return [...state.cases].sort((a,b)=>latest(b)-latest(a));
}
