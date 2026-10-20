(function () {
  'use strict';
  var finished = false;
  var timer;
  function element(tag, text) {
    var node = document.createElement(tag);
    if (text) node.textContent = text;
    return node;
  }
  // replaceChildren arrived later than the Android 8 WebView baseline.
  if (!Element.prototype.replaceChildren) {
    Element.prototype.replaceChildren = function () {
      while (this.firstChild) this.removeChild(this.firstChild);
      for (var i = 0; i < arguments.length; i++) {
        var item = arguments[i];
        this.appendChild(typeof item === 'string' ? document.createTextNode(item) : item);
      }
    };
  }
  function report(message) {
    if (finished) {
      if (window.CyberBoot.onRuntimeError) window.CyberBoot.onRuntimeError(message);
      return;
    }
    clearTimeout(timer);
    document.body.classList.remove('busy');
    var toolbar = document.getElementById('toolbar');
    var content = document.getElementById('content');
    toolbar.textContent = 'DB Manager';
    content.textContent = '';
    var box = element('div');
    box.className = 'bootStatus';
    box.appendChild(element('h2', 'Unable to start'));
    box.appendChild(element('p', 'Please retry. If this happens again, share the error details below.'));
    var details = element('pre', 'DB Manager 0.2.2\n' + message + '\n\n' + navigator.userAgent);
    details.className = 'bootDetails';
    box.appendChild(details);
    var retry = element('button', 'RETRY');
    retry.className = 'primary';
    retry.onclick = function () { window.location.reload(); };
    box.appendChild(retry);
    content.appendChild(box);
  }
  window.CyberBoot = {
    fail: function (error) { report(error && error.message ? error.message : String(error)); },
    ready: function () { finished = true; clearTimeout(timer); },
    onRuntimeError: null
  };
  window.addEventListener('error', function (event) {
    var target = event.target;
    if (target && target.tagName === 'SCRIPT') report('Could not load ' + target.getAttribute('src'));
    else if (event.message) report(event.message + (event.lineno ? ' (line ' + event.lineno + ')' : ''));
  }, true);
  window.addEventListener('unhandledrejection', function (event) {
    var reason = event.reason;
    report(reason && reason.message ? reason.message : String(reason));
  });
  var retry = document.getElementById('bootRetry');
  if (retry) retry.onclick = function () { window.location.reload(); };
  timer = setTimeout(function () { report('Startup timed out while opening the file manager.'); }, 20000);
}());
