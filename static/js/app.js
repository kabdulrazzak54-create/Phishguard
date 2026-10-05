// Shows a loading spinner and disables the button while a scan form is submitting.
document.querySelectorAll("form.scan-form").forEach(function (form) {
  form.addEventListener("submit", function () {
    var btn = form.querySelector("button[type=submit]");
    if (!btn) return;
    btn.querySelector(".spinner-border").classList.remove("d-none");
    btn.querySelector(".btn-label").textContent = "Analyzing...";
    setTimeout(function () { btn.disabled = true; }, 0);
  });
});
// Re-enable the button if the user navigates back (browser cache).
window.addEventListener("pageshow", function (e) {
  if (!e.persisted) return;
  document.querySelectorAll("form.scan-form button[type=submit]").forEach(function (b) {
    b.disabled = false; b.querySelector(".spinner-border").classList.add("d-none");
  });
});
