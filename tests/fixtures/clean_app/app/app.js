// The same interface, built correctly. The identifier lives in a data attribute,
// an attribute-value context where escaping the quote characters is sufficient,
// and the handler is a constant that reads it back at click time.
function esc(s) {
  return String(s)
    .split("&").join("&amp;")
    .split("<").join("&lt;")
    .split(">").join("&gt;")
    .split("\"").join("&quot;")
    .split("'").join("&#39;");
}

window.openItem = function (id) {
  document.getElementById("list").setAttribute("data-opened", id);
};

fetch("http://127.0.0.1:8732/api/list")
  .then(function (response) { return response.json(); })
  .then(function (data) {
    document.getElementById("list").innerHTML = data.items.map(function (item) {
      return "<button type=\"button\" data-item-id=\"" + esc(item.id) + "\""
        + " onclick=\"window.openItem(this.dataset.itemId)\">"
        + "<span>" + esc(item.title) + "</span></button>";
    }).join("");
  })
  .catch(function () { document.getElementById("list").textContent = "unreachable"; });
