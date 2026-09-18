// The same shapes as dataflow.js in the vulnerable fixture, but the escaper matches
// the context each value is placed in, and executable attributes are avoided.

function escapeForText(s) {
  return String(s)
    .split("&").join("&amp;")
    .split("<").join("&lt;")
    .split(">").join("&gt;")
    .split('"').join("&quot;")
    .split("'").join("&#39;");
}

function escapeForUrl(s) {
  return encodeURIComponent(String(s));
}

function renderUserItem(user) {
  const safeName = escapeForText(user.name);
  const html = '<button data-name="' + safeName + '">' + safeName + "</button>";
  document.getElementById("items").innerHTML = html;
}

function renderUserLink(user) {
  const html = '<a href="' + escapeForUrl(user.homepage) + '">profile</a>';
  document.getElementById("items").innerHTML = html;
}
