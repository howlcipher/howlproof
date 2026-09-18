// Patterns that a nearby-text or single-context analyser can miss. The escaper
// is adequate for HTML text but is then reused in a JavaScript string context
// inside an event-handler attribute and in a URL context.

function escapeForText(s) {
  return String(s)
    .split("&").join("&amp;")
    .split("<").join("&lt;")
    .split(">").join("&gt;")
    .split('"').join("&quot;");
}

function renderUserItem(user) {
  const safeName = escapeForText(user.name);
  const html = '<button onclick="logName(\'' + safeName + '\')">' + safeName + "</button>";
  document.getElementById("items").innerHTML = html;
}

function renderUserLink(user) {
  const home = escapeForText(user.homepage);
  const html = '<a href="' + home + '">profile</a>';
  document.getElementById("items").innerHTML = html;
}
