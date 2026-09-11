// The same renderer with an escaper adequate for every context it is used in,
// and no value placed inside an executable attribute.
function esc(s) {
  return String(s)
    .split("&").join("&amp;")
    .split("<").join("&lt;")
    .split(">").join("&gt;")
    .split("\"").join("&quot;")
    .split("'").join("&#39;");
}

function renderRow(item) {
  return "<button type=\"button\" data-item=\"" + esc(item.id) + "\">"
    + "<span class=\"title\">" + esc(item.title) + "</span></button>";
}

function renderNote(note) {
  setHTML(document.querySelector("#note"), "<p class=\"note\">" + esc(note.body) + "</p>");
}
