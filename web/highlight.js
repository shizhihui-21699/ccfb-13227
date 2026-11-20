// Syntactic highlighting for Solidity. Deliberately small and line-preserving:
// it must never change the text or line breaks the analyzer reported.
const KEYWORDS = new Set((
  'pragma solidity import as from is contract interface library abstract ' +
  'function modifier constructor receive fallback event error struct enum ' +
  'using for returns return if else for while do break continue throw emit ' +
  'revert require assert delete new try catch unchecked assembly true false ' +
  'public private internal external pure view payable constant immutable ' +
  'virtual override memory storage calldata anonymous indexed let'
).split(/\s+/));

const SOL_TYPE_RE = /^(u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|bytes([1-9]|[12][0-9]|3[0-2])?|address|bool|string|mapping|fixed|ufixed)$/;

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// highlightLine returns HTML for one source line, preserving every character.
function highlightLine(text) {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];

    // line comment
    if (c === '/' && text[i + 1] === '/') {
      out += '<span class="tok-cmt">' + esc(text.slice(i)) + '</span>';
      return out;
    }
    // block comment start (single-line only; multi-line handled below)
    if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end >= 0) {
        out += '<span class="tok-cmt">' + esc(text.slice(i, end + 2)) + '</span>';
        i = end + 2;
        continue;
      }
      out += '<span class="tok-cmt">' + esc(text.slice(i)) + '</span>';
      return out;
    }
    // strings
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === c) { j++; break; }
        j++;
      }
      out += '<span class="tok-str">' + esc(text.slice(i, j)) + '</span>';
      i = j;
      continue;
    }
    // numbers
    if (/[0-9]/.test(c) && (i === 0 || !/[\w$]/.test(text[i - 1]))) {
      let j = i;
      while (j < n && /[0-9a-fA-FxX_.]/.test(text[j])) j++;
      // unit suffix
      const rest = text.slice(j);
      const m = /^(ether|wei|gwei|seconds|minutes|hours|days|weeks)\b/.exec(rest);
      if (m) j += m[0].length;
      out += '<span class="tok-num">' + esc(text.slice(i, j)) + '</span>';
      i = j;
      continue;
    }
    // identifiers
    if (/[A-Za-z_$]/.test(c)) {
      let j = i;
      while (j < n && /[\w$]/.test(text[j])) j++;
      const word = text.slice(i, j);
      let cls = '';
      if (KEYWORDS.has(word)) cls = 'tok-kw';
      else if (SOL_TYPE_RE.test(word)) cls = 'tok-type';
      else if (text[j] === '(') cls = 'tok-fn';
      else if (word === 'pragma') cls = 'tok-pragma';
      out += cls ? '<span class="' + cls + '">' + esc(word) + '</span>' : esc(word);
      i = j;
      continue;
    }
    out += esc(c);
    i++;
  }
  return out;
}

window.SolHighlight = { highlightLine };
