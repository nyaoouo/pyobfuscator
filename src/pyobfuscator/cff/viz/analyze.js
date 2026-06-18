/* pyobfuscator analyze viewer — vanilla, no external deps.
 * Renders window.__PYOBF__ : { schema, scopes: [ {qualname, supported, source_lines,
 *   entry, blocks:[{id, stmts, lines:[a,b]|null, term}], flattened_source} ] }
 * Each scope -> a panel with original source (left) and an SVG control-flow graph
 * (right). Clicking a block highlights its source lines and vice versa.
 * Term kinds handled: goto | cond | ret  (later stages add raise | handler_dispatch). */
(function (global) {
  "use strict";
  const SVGNS = "http://www.w3.org/2000/svg";
  const CHARW = 6.8, LH = 15, PADX = 10, PADY = 6, GAPX = 36, GAPY = 58,
        MARGIN = 24, MAXCH = 46, MAXSTMT = 4;

  function h(tag, attrs, kids) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") e.className = attrs[k]; else e.setAttribute(k, attrs[k]);
    }
    if (kids) kids.forEach((c) => e.append(c));
    return e;
  }
  function s(tag, attrs) {
    const e = document.createElementNS(SVGNS, tag);
    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function trunc(t) { return t.length > MAXCH ? t.slice(0, MAXCH - 1) + "…" : t; }

  function succs(b) {
    const t = b.term;
    if (t.kind === "goto") return [t.target];
    if (t.kind === "cond") return [t.then, t.orelse];
    if (t.kind === "handler_dispatch" && t.handlers) return t.handlers.map((x) => x[1]);
    return [];
  }
  function termText(t) {
    if (t.kind === "goto") return "→ B" + t.target;
    if (t.kind === "cond") return "if " + t.test + "  ? B" + t.then + " : B" + t.orelse;
    if (t.kind === "ret") return t.value != null ? "return " + t.value : "return";
    if (t.kind === "raise") return "raise" + (t.exc ? " " + t.exc : "");
    if (t.kind === "handler_dispatch")
      return "except → " + t.handlers.map((h) => "B" + h[1]).join(", ");
    return t.kind;
  }
  function nodeLines(b, entry) {
    const lines = [{ c: "bid", t: "B" + b.id + (b.id === entry ? " ▸" : "") }];
    b.stmts.slice(0, MAXSTMT).forEach((x) => lines.push({ c: "", t: trunc(x) }));
    if (b.stmts.length > MAXSTMT)
      lines.push({ c: "", t: "… (+" + (b.stmts.length - MAXSTMT) + ")" });
    const t = b.term;
    if (t.kind === "cond") {
      lines.push({ c: "term", t: "if " + trunc(t.test) });
      lines.push({ c: "term", t: "T→B" + t.then + "  F→B" + t.orelse });
    } else {
      lines.push({ c: "term", t: termText(t) });
    }
    return lines;
  }

  function layout(blocks, entry) {
    const byId = {}; blocks.forEach((b) => (byId[b.id] = b));
    const layer = {}; const q = [];
    if (byId[entry] !== undefined) { layer[entry] = 0; q.push(entry); }
    while (q.length) {
      const id = q.shift();
      for (const sc of succs(byId[id])) {
        if (byId[sc] !== undefined && layer[sc] === undefined) {
          layer[sc] = layer[id] + 1; q.push(sc);
        }
      }
    }
    let maxL = 0; Object.values(layer).forEach((v) => (maxL = Math.max(maxL, v)));
    blocks.forEach((b) => { if (layer[b.id] === undefined) layer[b.id] = ++maxL; });
    return { byId, layer };
  }

  function defs() {
    const d = s("defs");
    const mk = (id, color) => {
      const m = s("marker", { id, viewBox: "0 0 10 10", refX: 9, refY: 5,
        markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
      m.append(s("path", { d: "M0,0 L10,5 L0,10 z", fill: color }));
      return m;
    };
    d.append(mk("arrow", "#7aa2f7"));
    d.append(mk("arrow-back", "#e0af68"));
    return d;
  }

  function edge(src, dst, label) {
    const back = dst.layer <= src.layer;
    let d;
    if (!back) {
      const x1 = src.cx, y1 = src.y + src.h, x2 = dst.cx, y2 = dst.y;
      d = `M${x1},${y1} C${x1},${y1 + GAPY / 2} ${x2},${y2 - GAPY / 2} ${x2},${y2}`;
    } else {
      const x1 = src.x + src.w, y1 = src.cy, x2 = dst.x + dst.w, y2 = dst.cy;
      const bow = Math.max(40, Math.abs(y1 - y2) / 2 + 30);
      d = `M${x1},${y1} C${x1 + bow},${y1} ${x2 + bow},${y2} ${x2},${y2}`;
    }
    const g = s("g");
    g.append(s("path", { class: "edge" + (back ? " back" : ""), d }));
    if (label) {
      const lx = back ? Math.max(src.x + src.w, dst.x + dst.w) + 28
                      : (src.cx + dst.cx) / 2;
      const ly = back ? (src.cy + dst.cy) / 2 : (src.y + src.h + dst.y) / 2;
      const tx = s("text", { class: "edge-label", x: lx, y: ly });
      tx.textContent = label; g.append(tx);
    }
    return g;
  }

  function nodeGroup(n) {
    const g = s("g", { class: "node", "data-bid": n.b.id });
    g.append(s("rect", { x: n.x, y: n.y, width: n.w, height: n.h, rx: 6 }));
    n.lines.forEach((l, i) => {
      const tx = s("text", { class: l.c, x: n.x + PADX, y: n.y + PADY + LH * (i + 1) - 3 });
      tx.textContent = l.t; g.append(tx);
    });
    return g;
  }

  function renderGraph(scope) {
    const { layer } = layout(scope.blocks, scope.entry);
    const nodes = {};
    scope.blocks.forEach((b) => {
      const lines = nodeLines(b, scope.entry);
      const w = Math.max(80, Math.max.apply(null, lines.map((l) => l.t.length)) * CHARW + 2 * PADX);
      const ht = lines.length * LH + 2 * PADY;
      nodes[b.id] = { b, lines, w, h: ht, layer: layer[b.id] };
    });
    const byLayer = {};
    scope.blocks.forEach((b) => { (byLayer[layer[b.id]] = byLayer[layer[b.id]] || []).push(b.id); });
    const keys = Object.keys(byLayer).map(Number).sort((a, b) => a - b);
    let totalW = 0; const rowW = {}, rowH = {};
    keys.forEach((L) => {
      let w = 0, hh = 0;
      byLayer[L].forEach((id) => { w += nodes[id].w + GAPX; hh = Math.max(hh, nodes[id].h); });
      rowW[L] = w - GAPX; rowH[L] = hh; totalW = Math.max(totalW, rowW[L]);
    });
    let y = MARGIN;
    keys.forEach((L) => {
      let x = MARGIN + (totalW - rowW[L]) / 2;
      byLayer[L].forEach((id) => {
        const n = nodes[id];
        n.x = x; n.y = y; n.cx = x + n.w / 2; n.cy = y + n.h / 2;
        x += n.w + GAPX;
      });
      y += rowH[L] + GAPY;
    });
    const svgW = totalW + 2 * MARGIN, svgH = y + MARGIN;
    const svg = s("svg", { width: svgW, height: svgH, viewBox: `0 0 ${svgW} ${svgH}` });
    svg.append(defs());
    scope.blocks.forEach((b) => {
      const n = nodes[b.id], t = b.term;
      const draw = (tid, label) => { if (nodes[tid] !== undefined) svg.append(edge(n, nodes[tid], label)); };
      if (t.kind === "goto") draw(t.target, "");
      else if (t.kind === "cond") { draw(t.then, "T"); draw(t.orelse, "F"); }
      else if (t.kind === "handler_dispatch" && t.handlers) t.handlers.forEach((hh) => draw(hh[1], "exc"));
    });
    scope.blocks.forEach((b) => svg.append(nodeGroup(nodes[b.id])));
    return svg;
  }

  function renderCode(cls, label, lines) {
    const box = h("div", { class: cls });
    const head = h("div", { class: "phead" }); head.textContent = label; box.append(head);
    (lines || []).forEach((sl) => {
      const ln = h("div", { class: "ln", "data-line": sl.n });
      ln.append(h("span", { class: "n" }, [document.createTextNode(String(sl.n))]));
      ln.append(document.createTextNode(sl.text));
      box.append(ln);
    });
    return box;
  }

  function wire(sec, scope) {
    const svg = sec.querySelector("svg");
    const detail = sec.querySelector(".detail");
    const byId = {}; scope.blocks.forEach((b) => (byId[b.id] = b));
    const clearSel = () => sec.querySelectorAll(".node.sel").forEach((n) => n.classList.remove("sel"));
    const clearHl = () => sec.querySelectorAll(".ln.hl").forEach((n) => n.classList.remove("hl"));
    const hl = (paneSel, range) => {
      if (!range) return;
      sec.querySelectorAll(paneSel + " .ln").forEach((ln) => {
        const n = +ln.dataset.line;
        if (n >= range[0] && n <= range[1]) ln.classList.add("hl");
      });
      const first = sec.querySelector(paneSel + ` .ln[data-line="${range[0]}"]`);
      if (first) first.scrollIntoView({ block: "nearest" });
    };

    const selectBlock = (bid) => {
      clearSel(); clearHl();
      const g = svg.querySelector(`.node[data-bid="${bid}"]`);
      if (g) g.classList.add("sel");
      const blk = byId[bid];
      hl(".src", blk.lines);        // original lines
      hl(".out", blk.flat_lines);   // where this state lands in the output
      detail.textContent = "B" + bid +
        (blk.lines ? "   src " + blk.lines[0] + "–" + blk.lines[1] : "   src —") +
        (blk.flat_lines ? "   ·   out " + blk.flat_lines[0] + "–" + blk.flat_lines[1] : "") +
        "\n" + (blk.stmts.length ? blk.stmts.join("\n") + "\n" : "") + termText(blk.term);
    };
    svg.querySelectorAll(".node").forEach((g) =>
      g.addEventListener("click", () => selectBlock(+g.dataset.bid)));

    const lineClick = (paneSel, key) =>
      sec.querySelectorAll(paneSel + " .ln").forEach((ln) =>
        ln.addEventListener("click", () => {
          const n = +ln.dataset.line;
          clearSel(); clearHl(); ln.classList.add("hl");
          const hit = scope.blocks.filter((b) => b[key] && n >= b[key][0] && n <= b[key][1]);
          hit.forEach((b) => {
            const g = svg.querySelector(`.node[data-bid="${b.id}"]`);
            if (g) g.classList.add("sel");
            hl(".src", b.lines); hl(".out", b.flat_lines);
          });
          detail.textContent = (paneSel === ".src" ? "src" : "out") + " line " + n + "   ⇄   " +
            (hit.length ? "blocks " + hit.map((b) => "B" + b.id).join(", ") : "(none)");
        }));
    lineClick(".src", "lines");
    lineClick(".out", "flat_lines");
  }

  function renderScope(scope) {
    const sec = h("section", { class: "scope" });
    const head = h("header");
    const q = h("span", { class: "q" }); q.textContent = scope.qualname; head.append(q);
    const badge = h("span", { class: "badge" + (scope.supported ? "" : " err") });
    badge.textContent = !scope.supported ? "unsupported"
      : scope.flattened === false ? "not flattened"
      : scope.blocks.length + " blocks";
    head.append(badge); sec.append(head);
    if (!scope.supported) {
      const u = h("div", { class: "unsupported" });
      u.textContent = scope.reason || "unsupported";
      sec.append(u); return sec;
    }
    if (scope.flattened === false) {
      const note = h("div", { class: "note" });
      note.textContent = scope.skip_reason || "not flattened";
      sec.append(note);
    }
    const body = h("div", { class: "body" });
    body.append(renderCode("src", "original", scope.source_lines));
    body.append(renderCode("out", "output (flattened)", scope.flattened_lines));
    const graphBox = h("div", { class: "graph" });
    graphBox.append(renderGraph(scope));
    body.append(graphBox); sec.append(body);
    const detail = h("div", { class: "detail" });
    detail.textContent = "click a block, or a line in original / output…";
    sec.append(detail);
    wire(sec, scope);
    return sec;
  }

  // Pass timeline: one source snapshot per plugin that changed the code (only-changed).
  // Clicking the flattened step scrolls to the per-scope CFG mind-maps below.
  function renderTimeline(passes, opts) {
    opts = opts || {};
    const sec = h("section", { class: "timeline" });
    const head = h("div", { class: "phead" });
    head.textContent = opts.title || "pass timeline — how the source changes, one snapshot per plugin";
    sec.append(head);
    const steps = h("div", { class: "steps" });
    const pane = h("div", { class: "code-pane" });
    sec.append(steps);
    sec.append(pane);

    const showStep = (st) => {
      pane.innerHTML = "";
      if (st.error) {
        const e = h("div", { class: "unsupported" });
        e.textContent = st.error;
        pane.append(e);
        return;
      }
      const chg = new Set(st.changed || []);
      (st.lines || []).forEach((sl) => {
        const ln = h("div", { class: "ln" + (chg.has(sl.n) ? " chg" : "") });
        ln.append(h("span", { class: "n" }, [document.createTextNode(String(sl.n))]));
        ln.append(document.createTextNode(sl.text));
        pane.append(ln);
      });
    };

    const chips = [];
    const select = (i, scroll) => {
      chips.forEach((c) => c.classList.remove("sel"));
      chips[i].classList.add("sel");
      showStep(passes[i]);
      if (scroll && passes[i].has_cfg) {
        const sc = document.querySelector(".scope");
        if (sc) sc.scrollIntoView({ block: "nearest" });
      }
    };
    passes.forEach((st, i) => {
      const cls = "chip" + (st.has_cfg ? " flat" : "") + (st.error ? " err" : "");
      const chip = h("div", { class: cls });
      const lab = h("span", { class: "lab" });
      lab.textContent = st.label || st.name;
      chip.append(lab);
      const sub = h("span", { class: "sub" });
      sub.textContent = st.error ? "error"
        : i === 0 ? "input"
        : (st.changed && st.changed.length) ? st.changed.length + " changed"
        : "no change";
      chip.append(sub);
      chip.addEventListener("click", () => select(i, true));
      steps.append(chip);
      chips.push(chip);
    });
    if (chips.length) select(chips.length - 1, false); // default: final step, no auto-scroll
    return sec;
  }

  function render(root, data) {
    root.innerHTML = "";
    if (data.passes && data.passes.length) root.append(renderTimeline(data.passes));
    (data.scopes || []).forEach((sc) => root.append(renderScope(sc)));
  }

  global.PYOBF = { render, renderTimeline };
})(window);
