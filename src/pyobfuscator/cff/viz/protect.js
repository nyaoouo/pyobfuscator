/* pyobfuscator protect (shell) viewer — vanilla, no external deps.
 * Renders window.__PYOBF_PROTECT__ : { schema, format, layers:[{name,bytes,ratio?,note?}],
 *   launcher_source, [assembled_lines, regions, launcher_passes] }.
 * The launcher carries the obfuscated body as a compressed+encrypted blob; this page shows the
 * packaging layers (byte sizes), and — once the core seam exists — how the launcher itself gets
 * flattened (reusing PYOBF.renderTimeline) plus a region-annotated assembled launcher. */
(function (global) {
  "use strict";

  function h(tag, attrs, kids) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") e.className = attrs[k]; else e.setAttribute(k, attrs[k]);
    }
    if (kids) kids.forEach((c) => e.append(c));
    return e;
  }
  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }
  function numbered(text) {
    return text.split("\n").map((t, i) => ({ n: i + 1, text: t }));
  }

  function renderLayers(layers) {
    const sec = h("section", { class: "layers" });
    const head = h("div", { class: "phead" });
    head.textContent = "packaging layers — the body's bytes through the packer";
    sec.append(head);
    const max = Math.max.apply(null, layers.map((l) => l.bytes || 0)) || 1;
    layers.forEach((l) => {
      const row = h("div", { class: "layer-row" });
      const name = h("span", { class: "lname" }); name.textContent = l.name; row.append(name);
      const track = h("span", { class: "track" });
      const bar = h("span", { class: "bar" });
      bar.style.width = Math.max(2, Math.round((l.bytes || 0) / max * 100)) + "%";
      track.append(bar); row.append(track);
      const meta = h("span", { class: "lmeta" });
      meta.textContent = fmtBytes(l.bytes || 0)
        + (l.ratio != null ? "  (" + (l.ratio * 100).toFixed(1) + "% of raw)" : "")
        + (l.note ? "  · " + l.note : "");
      row.append(meta);
      sec.append(row);
    });
    return sec;
  }

  function renderSource(title, lines, regions) {
    const box = h("section", { class: "lpane" });
    const head = h("div", { class: "phead" }); head.textContent = title; box.append(head);
    const tagFor = {};
    (regions || []).forEach((r) => {
      for (let n = r.lines[0]; n <= r.lines[1]; n++) if (!(n in tagFor)) tagFor[n] = r.label;
    });
    let lastTag = null;
    (lines || []).forEach((sl) => {
      const t = tagFor[sl.n];
      if (t && t !== lastTag) {
        const rh = h("div", { class: "region" }); rh.textContent = "▼ " + t; box.append(rh); lastTag = t;
      } else if (!t) {
        lastTag = null;
      }
      const ln = h("div", { class: "ln" });
      ln.append(h("span", { class: "n" }, [document.createTextNode(String(sl.n))]));
      ln.append(document.createTextNode(sl.text));
      box.append(ln);
    });
    return box;
  }

  function renderProtect(root, data) {
    root.innerHTML = "";
    root.append(renderLayers(data.layers || []));
    // launcher pass-timeline (present once the core seam exists) — reuse the shared renderer
    if (data.launcher_passes && data.launcher_passes.length && global.PYOBF && global.PYOBF.renderTimeline) {
      root.append(global.PYOBF.renderTimeline(data.launcher_passes,
        { title: "launcher pipeline — how the shell itself gets flattened" }));
    }
    // assembled (pre-flatten) launcher annotated by region, else the final launcher source
    if (data.assembled_lines && data.assembled_lines.length) {
      root.append(renderSource("assembled launcher (pre-flatten) — annotated by region",
        data.assembled_lines, data.regions));
    } else if (data.launcher_source) {
      root.append(renderSource("final launcher source", numbered(data.launcher_source), []));
    }
  }

  global.PYOBF = global.PYOBF || {};
  global.PYOBF.renderProtect = renderProtect;
})(window);
