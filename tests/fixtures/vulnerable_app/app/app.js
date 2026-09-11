// The fixture interface, built the wrong way on purpose. It reuses the escaper
// from src/render.js, which does not escape the single quote, and places its
// output inside a JavaScript string literal in an event-handler attribute.
function esc(s) {
  return String(s)
    .split("&").join("&amp;")
    .split("<").join("&lt;")
    .split(">").join("&gt;")
    .split("\"").join("&quot;");
}

window.openItem = function (id) {
  document.getElementById("list").setAttribute("data-opened", id);
};

fetch("http://127.0.0.1:8731/api/list")
  .then(function (response) { return response.json(); })
  .then(function (data) {
    document.getElementById("list").innerHTML = data.items.map(function (item) {
      return "<button type=\"button\" onclick=\"window.openItem('" + esc(item.id) + "')\">"
        + "<span>" + esc(item.title) + "</span></button>";
    }).join("");
  })
  .catch(function () { document.getElementById("list").textContent = "unreachable"; });
