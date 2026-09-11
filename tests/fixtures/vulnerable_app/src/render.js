// A renderer with an escaper that is correct for HTML text and wrong for a
// JavaScript string literal: it never escapes the single quote.
function esc(s) {
  return String(s)
    .split("&").join("&amp;")
    .split("<").join("&lt;")
    .split(">").join("&gt;")
    .split("\"").join("&quot;");
}

function renderRow(item) {
  return "<button type=\"button\" onclick=\"openItem('" + esc(item.id) + "')\">"
    + "<span class=\"title\">" + esc(item.title) + "</span></button>";
}

function renderNote(note) {
  setHTML(document.querySelector("#note"), "<p class=\"note\">" + note.body + "</p>");
}
