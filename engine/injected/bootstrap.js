// Sieve's own runner around Brave's procedural filter applier, which only selects
// elements. Runs each filter at DOMContentLoaded, then again whenever elements
// come or go, at most once per throttle period.
// eslint-disable-next-line @typescript-eslint/no-unused-vars -- the payload calls it
function sieveRunProcedural(applier, filters) {
  const THROTTLE_MS = 100;
  const compiled = [];
  // A style action's declarations, read once by the browser's own parser.
  const declaredStyle = (action) => {
    if (action?.type !== "style") return null;
    const declared = document.createElement("div").style;
    declared.cssText = action.arg;
    return declared;
  };
  for (const filter of filters) {
    try {
      compiled.push({ selector: applier.compileProceduralSelector(filter.selector), action: filter.action, declared: declaredStyle(filter.action) });
    } catch {
      // One filter the applier cannot compile must not cost the others.
    }
  }

  const hide = (element) => {
    const { style } = element;
    if (style.getPropertyValue("display") !== "none" || style.getPropertyPriority("display") !== "important") {
      style.setProperty("display", "none", "important");
    }
  };

  // Writes only what differs, as `hide` does: a page that overrides the style gets
  // it put back, and a pass with nothing to do changes nothing.
  const applyStyle = (element, declared) => {
    const { style } = element;
    for (const name of declared) {
      const value = declared.getPropertyValue(name);
      const priority = declared.getPropertyPriority(name);
      if (style.getPropertyValue(name) !== value || style.getPropertyPriority(name) !== priority) {
        style.setProperty(name, value, priority);
      }
    }
  };

  const act = (element, filter) => {
    const action = filter.action;
    if (!action) return hide(element);
    if (action.type === "remove") return element.remove();
    if (action.type === "remove-attr") return element.removeAttribute(action.arg);
    if (action.type === "remove-class") return element.classList.remove(action.arg);
    if (filter.declared) applyStyle(element, filter.declared);
  };

  const pass = () => {
    for (const filter of compiled) {
      try {
        for (const element of applier.applyCompiledSelector(filter.selector)) act(element, filter);
      } catch {
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
