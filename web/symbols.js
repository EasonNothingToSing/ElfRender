/* symbols.js - Expand/collapse + stats + export */
(function () {
  'use strict';

  const statsEl = document.getElementById('stats');
  const treeRoot = document.getElementById('tree');
  const metaSource = document.getElementById('metaSource');

  // Load JSON
  fetch('symbols.json')
    .then(r => {
      if (!r.ok) throw new Error('Failed to load symbols.json');
      return r.json();
    })
    .then(payload => init(payload))
    .catch(err => {
      metaSource.textContent = String(err);
      console.error(err);
    });

  function init(payload) {
    const DATA = payload.tree || {};
    const STATS = payload.stats || { total_size: 0, dir_count: 0, file_count: 0, symbol_count: 0 };
    const META = payload.meta || { elf: '', generated_at: '' };

    metaSource.textContent = `数据来自：${META.elf}`;
    const genMetaEl = document.getElementById('genMeta');
    if (genMetaEl) genMetaEl.textContent = `${META.elf} · 生成于 ${META.generated_at}`;

    renderStats(STATS);
    renderTree(DATA, treeRoot);
    wireControls(payload);
    // Initial state: collapse all
    document.getElementById('collapseAll').click();
  }

  function renderStats(STATS) {
    statsEl.innerHTML = `
      <span class="stat" aria-label="目录数">目录数：${STATS.dir_count}</span>
      <span class="stat" aria-label="文件数">文件数：${STATS.file_count}</span>
      <span class="stat" aria-label="符号数">符号数：${STATS.symbol_count}</span>
      <span class="stat" aria-label="总字节">总字节：${STATS.total_size}</span>
    `;
  }

  function createNode(label, size, cls, isToggle) {
    const span = document.createElement('span');
    span.className = `node ${cls}` + (isToggle ? ' toggle' : '');
    span.setAttribute('role', isToggle ? 'treeitem' : 'none');
    span.setAttribute('aria-expanded', isToggle ? 'false' : 'false');
    span.innerHTML = label + (size != null ? ` <span class="size">(${size} bytes)</span>` : '');
    return span;
  }

  function renderTree(node, mount) {
    const ul = document.createElement('ul');
    mount.appendChild(ul);

    const entries = Object.entries(node).sort((a, b) => {
      const A = a[1], B = b[1];
      if (A.__type__ !== B.__type__) return A.__type__ === 'dir' ? -1 : 1;
      const sa = A.__size__ || 0, sb = B.__size__ || 0;
      if (sb !== sa) return sb - sa;
      return a[0].localeCompare(b[0]);
    });

    for (const [name, data] of entries) {
      const li = document.createElement('li');
      ul.appendChild(li);

      if (data.__type__ === 'dir') {
        const nodeEl = createNode(`📁 ${name}`, data.__size__, 'dir', true);
        li.appendChild(nodeEl);
        const child = document.createElement('ul');
        child.className = 'hidden';
        li.appendChild(child);
        renderTree(data.__children__, child);
      } else {
        const nodeEl = createNode(`📄 ${name}`, data.__size__, 'file', true);
        li.appendChild(nodeEl);
        const child = document.createElement('ul');
        child.className = 'hidden';
        li.appendChild(child);

        const symbols = Array.from(data.__symbols__ || []).sort((a, b) => (b.size || 0) - (a.size || 0));
        for (const sym of symbols) {
          const li2 = document.createElement('li');
          child.appendChild(li2);
          const s = document.createElement('span');
          s.className = 'node symbol';
          s.textContent = `🔹 ${sym.name}`;
          const sizeEl = document.createElement('span');
          sizeEl.className = 'size';
          sizeEl.textContent = `${sym.size} bytes`;
          s.appendChild(sizeEl);
          li2.appendChild(s);
        }
      }
    }
  }

  function setAll(open) {
    document.querySelectorAll('.toggle').forEach(t => {
      const next = t.nextElementSibling;
      if (!next) return;
      if (open) {
        next.classList.remove('hidden');
        t.classList.add('open');
        t.setAttribute('aria-expanded', 'true');
      } else {
        next.classList.add('hidden');
        t.classList.remove('open');
        t.setAttribute('aria-expanded', 'false');
      }
    });
  }

  function wireControls(payload) {
    const treeRoot = document.getElementById('tree');

    // Expand/collapse (event delegation)
    treeRoot.addEventListener('click', (e) => {
      const t = e.target.closest('.toggle');
      if (!t) return;
      const ul = t.nextElementSibling;
      if (!ul) return;
      ul.classList.toggle('hidden');
      const open = !ul.classList.contains('hidden');
      t.classList.toggle('open', open);
      t.setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    document.getElementById('expandAll').addEventListener('click', () => setAll(true));
    document.getElementById('collapseAll').addEventListener('click', () => setAll(false));

    // Export
    function download(filename, text) {
      const blob = new Blob([text], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    document.getElementById('downloadJSON').addEventListener('click', () => {
      // Download symbols.json as-is
      fetch('symbols.json').then(r => r.text()).then(txt => download('symbols.json', txt));
    });

    function flattenCSV(tree, prefix = []) {
      const rows = [];
      for (const [name, v] of Object.entries(tree)) {
        if (v.__type__ === 'dir') {
          rows.push([ [...prefix, name].join('/'), '', '', v.__size__ ]);
          rows.push(...flattenCSV(v.__children__, [...prefix, name]));
        } else {
          rows.push([ [...prefix].join('/'), name, '', v.__size__ ]);
          for (const sym of v.__symbols__ || []) {
            rows.push([ [...prefix].join('/'), name, sym.name, sym.size ]);
          }
        }
      }
      return rows;
    }

    document.getElementById('downloadCSV').addEventListener('click', () => {
      fetch('symbols.json').then(r => r.json()).then(payloadFull => {
        const DATA = payloadFull.tree || {};
        const rows = flattenCSV(DATA);
        let csv = 'directory,file,symbol,size_bytes\n';
        for (const r of rows) {
          csv += r.map(x => String(x).replace(/"/g, '""')).map(x => `"${x}"`).join(',') + '\n';
        }
        download('symbols.csv', csv);
      });
    });
  }
})();
