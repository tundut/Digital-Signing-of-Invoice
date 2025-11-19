(function(){
  // Prevent duplicate init
  if (window.__UI_INIT__) return; window.__UI_INIT__ = true;

  // Page transitions: intercept internal links
  function isInternalLink(a){
    if (!a || !a.href) return false;
    const url = new URL(a.href, window.location.origin);
    return url.origin === window.location.origin;
  }

  function setupTransitions(){
    document.addEventListener('click', function(e){
      const a = e.target.closest('a');
      if(!a) return;
      if(a.target === '_blank' || a.hasAttribute('download') || a.getAttribute('href')?.startsWith('#')) return;
      if(!isInternalLink(a)) return;
      e.preventDefault();
      document.body.classList.add('page-exit');
      setTimeout(()=>{ window.location.href = a.href; }, 230);
    });
    window.addEventListener('pageshow', ()=>{
      document.body.classList.remove('page-exit');
    });
  }

  // Reveal animations for cards/panels
  function setupReveal(){
    const els = document.querySelectorAll('.card-glass, .panel-glass');
    els.forEach((el, i)=>{
      el.classList.add('reveal');
      setTimeout(()=>{ el.classList.add('show'); }, 100 + i*60);
    });
  }

  // Hover tilt apply to cards and panels
  function setupTilt(){
    if (!window.VanillaTilt) return;
    const targets = document.querySelectorAll('.card-glass, .panel-glass');
    if (!targets.length) return;
    if (window.__TILT_INIT__) return; window.__TILT_INIT__ = true;
    VanillaTilt.init(targets, { max: 4, speed: 400, glare: true, 'max-glare': 0.08, scale: 1.005 });
  }

  document.addEventListener('DOMContentLoaded', function(){
    setupTransitions();
    setupReveal();
    setupTilt();
  });
})();
