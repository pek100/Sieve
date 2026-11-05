// Sieve's own runner around Brave's procedural filter applier, which only selects
// elements. Runs each filter at DOMContentLoaded, then again whenever elements
// come or go, at most once per throttle period.
function sieveRunProcedural(applier, filters) {
  const THROTTLE_MS = 100;
  const compiled = [];
  for (const filter of filters) {
    try {
      compiled.push({ selector: applier.compileProceduralSelector(filter.selector), action: filter.action, styled: new WeakSet() });
    } catch (_) {
      // One filter the applier cannot compile must not cost the others.
    }
  }

  const hide = (element) => {
    const { style } = element;
    if (style.getPropertyValue("display") !== "none" || style.getPropertyPriority("display") !== "important") {
      style.setProperty("display", "none", "important");
    }
  };

  const act = (element, filter) => {
    const action = filter.action;
    if (!action) return hide(element);
    if (action.type === "remove") return element.remove();
    if (action.type === "remove-attr") return element.removeAttribute(action.arg);
    if (action.type === "remove-class") return element.classList.remove(action.arg);
    if (action.type === "style" && !filter.styled.has(element)) {
      filter.styled.add(element);
      element.style.cssText += ";" + action.arg;
    }
  };

  const pass = () => {
    for (const filter of compiled) {
      try {
        for (const element of applier.applyCompiledSelector(filter.selector)) act(element, filter);
      } catch (_) {
        // A filter can throw on one page's DOM; the rest still run.
      }
    }
  };

  const start = () => {
    pass();
    let pending = false;
    // Only added and removed nodes, so a pass wakes the observer for its own work
    // only by removing an element, and the next pass then finds nothing to do.
    new MutationObserver(() => {
      if (pending) return;
      pending = true;
      setTimeout(() => {
        pending = false;
        pass();
      }, THROTTLE_MS);
    }).observe(document.documentElement, { childList: true, subtree: true });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
}
