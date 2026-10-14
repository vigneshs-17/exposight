/**
 * Landing page pointer tilt (C-UI-1) and pill-nav active state (C-UI-2).
 * All other motion is CSS (landing.css). Tilt only sets CSS custom properties
 * (--rx, --ry, --mx, --my) on .tilt elements through style.setProperty, which the
 * strict CSP allows. Off for reduced motion and for touch/coarse pointers.
 * The pill nav only toggles a class and aria-current. The header Sign in label reads
 * "Open dashboard" when a Supabase session key exists in sessionStorage (C-UI-4).
 * No setAttribute('style'), no DOM html injection.
 */

document.addEventListener("DOMContentLoaded", function () {
  var finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  var MAX_DEG = 7;

  function reset(el) {
    el.style.setProperty("--rx", "0deg");
    el.style.setProperty("--ry", "0deg");
  }

  // Signed in already (same tab): the dashboard keeps its Supabase session in sessionStorage
  // under "sb-<project>-auth-token". Only key names are checked; the token is never read,
  // parsed or sent. A label hint only: /app still verifies the session (C-UI-4).
  var signIn = document.querySelector(".landing-header .landing-signin-btn");
  try {
    for (var i = 0; signIn && i < window.sessionStorage.length; i++) {
      if (/^sb-.+-auth-token$/.test(window.sessionStorage.key(i))) {
        signIn.textContent = "Open dashboard";
        break;
      }
    }
  } catch (err) {
    // Storage blocked (privacy mode, sandbox): keep "Sign in".
  }

  // Floating pill nav: hidden (class only) while the hero is in view, so it never covers
  // the hero; without JavaScript it simply stays visible.
  var pillNav = document.querySelector(".pill-nav");
  var hero = document.getElementById("hero");
  if ("IntersectionObserver" in window && pillNav && hero) {
    pillNav.classList.add("is-hidden");
    new IntersectionObserver(function (entries) {
      pillNav.classList.toggle("is-hidden", entries[0].isIntersecting);
    }, { rootMargin: "-64px 0px 0px 0px" }).observe(hero);
  }

  // Mark the link of the section in view (class + aria-current only).
  var pillLinks = document.querySelectorAll(".pill-nav-link");
  if ("IntersectionObserver" in window && pillLinks.length) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) {
          return;
        }
        pillLinks.forEach(function (link) {
          var active = link.getAttribute("href") === "#" + entry.target.id;
          link.classList.toggle("is-active", active);
          if (active) {
            link.setAttribute("aria-current", "true");
          } else {
            link.removeAttribute("aria-current");
          }
        });
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    document.querySelectorAll("section[data-nav]").forEach(function (section) {
      observer.observe(section);
    });
  }

  document.querySelectorAll(".tilt").forEach(function (el) {
    el.addEventListener("pointermove", function (event) {
      if (!finePointer.matches || reducedMotion.matches) {
        return;
      }
      var rect = el.getBoundingClientRect();
      var x = (event.clientX - rect.left) / rect.width;
      var y = (event.clientY - rect.top) / rect.height;
      el.style.setProperty("--ry", ((x - 0.5) * 2 * MAX_DEG).toFixed(2) + "deg");
      el.style.setProperty("--rx", ((0.5 - y) * 2 * MAX_DEG).toFixed(2) + "deg");
      el.style.setProperty("--mx", (x * 100).toFixed(1) + "%");
      el.style.setProperty("--my", (y * 100).toFixed(1) + "%");
    });
    el.addEventListener("pointerleave", function () {
      reset(el);
    });
  });
});
