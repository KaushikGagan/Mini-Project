// Password visibility toggle
function togglePass(id, btn) {
  const input = document.getElementById(id);
  const isHidden = input.type === "password";
  input.type = isHidden ? "text" : "password";
  if (btn) btn.textContent = isHidden ? "🙈" : "👁";
}

// Live date on dashboard
const dateEl = document.getElementById("live-date");
if (dateEl) {
  const fmt = new Intl.DateTimeFormat("en-IN", {
    weekday: "long", year: "numeric", month: "long", day: "numeric"
  });
  dateEl.textContent = fmt.format(new Date());
}
