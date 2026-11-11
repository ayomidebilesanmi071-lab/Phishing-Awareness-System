/* PARS client-side behaviour - progressive enhancement only.
   All security decisions are enforced on the server. */

(function () {
  "use strict";

  function onReady(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  onReady(function () {
    // --- Mobile sidebar toggle -------------------------------------------
    var toggle = document.getElementById("menuToggle");
    if (toggle) {
      toggle.addEventListener("click", function () {
        document.body.classList.toggle("sidebar-open");
      });
      // Close the sidebar when a navigation link is chosen on small screens.
      document.querySelectorAll(".sidebar-nav a").forEach(function (link) {
        link.addEventListener("click", function () {
          if (window.innerWidth <= 900) {
            document.body.classList.remove("sidebar-open");
          }
        });
      });
    }

    // --- Auto-dismiss flash messages --------------------------------------
    document.querySelectorAll(".alert").forEach(function (el) {
      setTimeout(function () {
        el.style.opacity = "0";
        setTimeout(function () { el.remove(); }, 350);
      }, 6000);
    });

    // --- Confirm dialogs for destructive forms ------------------------------
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (!window.confirm(form.getAttribute("data-confirm"))) {
          event.preventDefault();
        }
      });
    });

    // --- Copy-to-clipboard buttons (e.g. suspicious links) -------------------
    document.querySelectorAll("[data-copy]").forEach(function (el) {
      el.addEventListener("click", function () {
        var text = el.getAttribute("data-copy");
        var done = function () {
          var original = el.textContent;
          el.textContent = "Copied!";
          setTimeout(function () { el.textContent = original; }, 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, done);
        } else {
          // Fallback for older browsers.
          var ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); } catch (e) { /* ignore */ }
          document.body.removeChild(ta);
          done();
        }
      });
    });
  });
})();
