/* MAVR UI client glue. Keep dependencies zero. */
(function () {
  "use strict";

  function getToken() {
    var el = document.getElementById("api-token");
    return el ? el.value : "";
  }

  function authHeaders(extra) {
    var h = Object.assign({}, extra || {});
    var t = getToken();
    if (t) h["Authorization"] = "Bearer " + t;
    return h;
  }

  window.mavrAuthHeaders = authHeaders;
  window.mavrGetToken = getToken;

  // --- kill switch banner (every page) ---
  function refreshKillSwitch() {
    fetch("/api/kill_switch", { headers: authHeaders() })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (state) {
        if (!state) return;
        var banner = document.getElementById("ks-banner");
        if (!banner) return;
        var active = !!state.is_active;
        banner.dataset.state = active ? "on" : "off";
        banner.querySelector("span").textContent = active
          ? "ON — " + (state.reason || "")
          : "off";
      })
      .catch(function () {});
  }
  if (document.readyState !== "loading") refreshKillSwitch();
  else document.addEventListener("DOMContentLoaded", refreshKillSwitch);
  setInterval(refreshKillSwitch, 5000);
})();
